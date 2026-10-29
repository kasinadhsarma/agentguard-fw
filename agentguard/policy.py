"""Policy engine: decide whether a tool call may run.

Rules, evaluated in order. The first rule that fires decides.

  R1  a target not authorized by the user, but named in untrusted
      content, on a risky tool                     -> BLOCK
  R2  the call copies text from sensitive data and
      sends it to a target the user did not name   -> BLOCK
  R5  arguments violate the tool's declared JSON schema
                                                   -> BLOCK
  R3  a target that nobody named (invented by the
      agent) on a risky tool                       -> CONFIRM
  R4  every target is user-authorized but the
      context holds a likely injection             -> CONFIRM
  R0  otherwise                                    -> ALLOW

Unknown tools are treated as risky (fail closed).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detector import SUSPICIOUS_THRESHOLD
from .models import Decision, ToolRisk, Verdict
from .taint import TaintTracker
from .tool_schema import (
    ToolSpec,
    infer_profile,
    parse_tool_definitions,
    validate_arguments,
)


@dataclass(frozen=True)
class ToolProfile:
    """Risk class plus the arguments that name who or what is affected."""

    risk: ToolRisk
    target_args: tuple[str, ...] = ()


DEFAULT_PROFILES: dict[str, ToolProfile] = {
    'fetch_page': ToolProfile(ToolRisk.READ, ('url',)),
    'read_file': ToolProfile(ToolRisk.SENSITIVE_READ, ('path',)),
    'send_email': ToolProfile(ToolRisk.SIDE_EFFECT, ('to', 'cc', 'bcc')),
    'http_post': ToolProfile(ToolRisk.SIDE_EFFECT, ('url',)),
    'write_file': ToolProfile(ToolRisk.SIDE_EFFECT, ('path',)),
    'delete_file': ToolProfile(ToolRisk.SIDE_EFFECT, ('path',)),
    'run_shell': ToolProfile(ToolRisk.SIDE_EFFECT, ('command',)),
}

# unknown tools get this profile so they fail closed
UNKNOWN_PROFILE = ToolProfile(ToolRisk.SIDE_EFFECT, ())


@dataclass
class PolicyConfig:
    """Tunable settings for the policy engine."""

    profiles: dict[str, ToolProfile] = field(
        default_factory=lambda: dict(DEFAULT_PROFILES),
    )
    suspicious_threshold: float = SUSPICIOUS_THRESHOLD
    # declared schemas, used for argument validation (rule R5)
    schemas: dict[str, ToolSpec] = field(default_factory=dict)
    # names whose profile was generated (and may be generated again)
    generated: set[str] = field(default_factory=set)

    def register_tools(
        self,
        definitions: list[dict],
        replace: bool = False,
    ) -> list[dict]:
        """Register tools from framework definitions.

        Every tool's schema is stored for validation. A risk profile is
        generated unless one already exists: hand-written profiles win,
        unless replace is True. Returns one summary dictionary per tool
        so the caller can review what was inferred.
        """
        summaries: list[dict] = []
        for spec in parse_tool_definitions(definitions):
            self.schemas[spec.name] = spec
            generated = infer_profile(spec)

            hand_written = (
                spec.name in self.profiles
                and spec.name not in self.generated
            )
            if hand_written and not replace:
                profile = self.profiles[spec.name]
                source = 'explicit'
                reason = 'a hand-written profile exists and was kept'
            else:
                profile = ToolProfile(generated.risk, generated.target_args)
                self.profiles[spec.name] = profile
                self.generated.add(spec.name)
                source = 'generated'
                reason = generated.reason

            summaries.append({
                'tool': spec.name,
                'risk': profile.risk.value,
                'target_args': list(profile.target_args),
                'source': source,
                'reason': reason,
            })
        return summaries


def targets_of(profile: ToolProfile, arguments: dict) -> list[str]:
    """Return the non-empty string values of the target arguments."""
    values: list[str] = []
    for name in profile.target_args:
        raw = arguments.get(name)
        if isinstance(raw, str) and raw.strip():
            values.append(raw)
        elif isinstance(raw, (list, tuple)):
            values.extend(str(entry) for entry in raw if str(entry).strip())
    return values


class PolicyEngine:
    """Applies the rule list to a tool call using the session's taint data."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        """Create an engine with default or custom settings."""
        self.config = config or PolicyConfig()

    def profile_for(self, tool: str) -> ToolProfile:
        """Look up a tool's profile, failing closed for unknown tools."""
        return self.config.profiles.get(tool, UNKNOWN_PROFILE)

    def evaluate(
        self,
        tool: str,
        arguments: dict,
        tracker: TaintTracker,
    ) -> Decision:
        """Return the decision for one proposed tool call."""
        profile = self.profile_for(tool)
        targets = targets_of(profile, arguments)
        risky = profile.risk != ToolRisk.READ

        unauthorized = [
            target
            for target in targets
            if not tracker.is_user_authorized(target)
        ]

        # R1: risky call aimed at a target that only untrusted content named
        if risky:
            for target in unauthorized:
                origin = tracker.untrusted_origin(target)
                if origin is not None:
                    return Decision(
                        verdict=Verdict.BLOCK,
                        rule_id='R1',
                        reason=(
                            'target "' + target + '" came from untrusted '
                            'content (' + origin.source + '), not from '
                            'the user'
                        ),
                        tool=tool,
                        args=arguments,
                        evidence=[_preview(origin.text, target)],
                    )

        # R2: payload copies sensitive data toward an unauthorized target
        leak = tracker.exfiltrated_span(arguments)
        if leak is not None and (unauthorized or not targets) and risky:
            sensitive, span = leak
            return Decision(
                verdict=Verdict.BLOCK,
                rule_id='R2',
                reason=(
                    'call copies data read from ' + sensitive.source +
                    ' to a target the user did not authorize'
                ),
                tool=tool,
                args=arguments,
                evidence=['copied text: "' + span + '"'],
            )
        if leak is not None and not risky and unauthorized:
            sensitive, span = leak
            return Decision(
                verdict=Verdict.BLOCK,
                rule_id='R2',
                reason=(
                    'read-only call smuggles data from ' + sensitive.source +
                    ' in its arguments'
                ),
                tool=tool,
                args=arguments,
                evidence=['copied text: "' + span + '"'],
            )

        # R5: arguments that do not fit the tool's declared schema
        spec = self.config.schemas.get(tool)
        if spec is not None:
            problems = validate_arguments(spec, arguments)
            if problems:
                return Decision(
                    verdict=Verdict.BLOCK,
                    rule_id='R5',
                    reason=(
                        'arguments violate the declared schema of "' +
                        tool + '"'
                    ),
                    tool=tool,
                    args=arguments,
                    evidence=problems[:5],
                )

        # R3 hardened: a made-up target while the context looks poisoned is
        # blocked, not asked about, so a habit "yes" cannot let it through
        if (
            risky and unauthorized
            and tracker.max_injection_score()
            >= self.config.suspicious_threshold
        ):
            return Decision(
                verdict=Verdict.BLOCK,
                rule_id='R3',
                reason=(
                    'target "' + unauthorized[0] + '" was not named by the '
                    'user and the context contains a likely injection '
                    '(score ' + format(tracker.max_injection_score(), '.2f')
                    + ')'
                ),
                tool=tool,
                args=arguments,
            )

        # R6: a side-effect call whose short identifier argument (a file
        # id, a name, a password) was named only by untrusted content
        if profile.risk == ToolRisk.SIDE_EFFECT:
            odd = untrusted_only_value(arguments, profile, tracker)
            if odd is not None:
                return Decision(
                    verdict=Verdict.CONFIRM,
                    rule_id='R6',
                    reason=(
                        'argument value "' + odd + '" appears only in '
                        'untrusted content, not in the user\'s request'
                    ),
                    tool=tool,
                    args=arguments,
                )

        # R3: target the agent made up, on a risky tool
        if risky and unauthorized:
            return Decision(
                verdict=Verdict.CONFIRM,
                rule_id='R3',
                reason=(
                    'target "' + unauthorized[0] + '" was not named by the '
                    'user; ask before proceeding'
                ),
                tool=tool,
                args=arguments,
            )

        # unknown tools with no declared targets always need a human
        if tool not in self.config.profiles:
            return Decision(
                verdict=Verdict.CONFIRM,
                rule_id='R3',
                reason='unknown tool "' + tool + '" is not in the policy',
                tool=tool,
                args=arguments,
            )

        # a generated side-effect profile that found no target argument
        # cannot be checked for origin, so a human must look at the call
        if (
            tool in self.config.generated
            and profile.risk == ToolRisk.SIDE_EFFECT
            and not profile.target_args
        ):
            return Decision(
                verdict=Verdict.CONFIRM,
                rule_id='R3',
                reason=(
                    'tool "' + tool + '" changes things but has no '
                    'recognizable target argument; confirm this call'
                ),
                tool=tool,
                args=arguments,
            )

        # R4: authorized call, but the context looks poisoned
        score = tracker.max_injection_score()
        if risky and score >= self.config.suspicious_threshold:
            return Decision(
                verdict=Verdict.CONFIRM,
                rule_id='R4',
                reason=(
                    'context contains a likely injection (score ' +
                    format(score, '.2f') + '); confirm this action'
                ),
                tool=tool,
                args=arguments,
            )

        return Decision(
            verdict=Verdict.ALLOW,
            rule_id='R0',
            reason='all targets are user-authorized and context is clean',
            tool=tool,
            args=arguments,
        )


# argument names that carry free text the agent writes itself; copying
# page text into them is normal (a summary), so R6 ignores them
FREE_TEXT_ARGS = frozenset({
    'body', 'content', 'text', 'message', 'subject', 'description',
    'summary', 'note', 'notes', 'comment', 'title', 'reason', 'caption',
})
R6_MAX_LENGTH = 80
R6_MIN_LENGTH = 4


def _is_id_name(name: str) -> bool:
    """True for argument names like id, file_id, fileId, order-id."""
    lowered = name.lower().replace('-', '_')
    return lowered == 'id' or lowered.endswith('_id') or (
        name.endswith('Id') and len(name) > 2
    )


def untrusted_only_value(
    arguments: dict,
    profile: ToolProfile,
    tracker: TaintTracker,
) -> str | None:
    """Return a short argument value that only untrusted content named.

    Target arguments are handled by R1 and R3, and free-text arguments are
    skipped. Values shorter than a few characters are skipped because they
    match by chance (the number "13" appears in any page), except in
    arguments whose name says they are an id, where a short value is the
    whole point (delete_file(file_id="13")).
    """
    for name, raw in arguments.items():
        if name in profile.target_args or name.lower() in FREE_TEXT_ARGS:
            continue
        if not isinstance(raw, str):
            continue
        value = raw.strip()
        shortest = 1 if _is_id_name(name) else R6_MIN_LENGTH
        if not shortest <= len(value) <= R6_MAX_LENGTH:
            continue
        if tracker.is_user_authorized(value):
            continue
        if tracker.untrusted_origin(value) is not None:
            return value
    return None


def _preview(text: str, needle: str, radius: int = 60) -> str:
    """Show where in the untrusted text the target was named."""
    index = text.lower().find(needle.lower())
    if index == -1:
        return ' '.join(text[: radius * 2].split())
    left = max(0, index - radius)
    right = min(len(text), index + len(needle) + radius)
    return '...' + ' '.join(text[left:right].split()) + '...'
