# AgentGuard architecture

All diagrams are Mermaid. GitHub, GitLab, VS Code and most Markdown viewers render them inline.
The sources live in `diagrams/*.mmd`; this file is generated from them. Version 0.4.

## System context

Where the firewall sits. Content on the way in is labeled; tool calls on the way out are authorized.

```mermaid
flowchart LR
    U["User"]
    W["Web pages, files, email, tool output"]
    A["AI agent (LLM)"]
    FW["AgentGuard firewall"]
    T["Tools: fetch_page, read_file, send_email, http_post, ..."]

    U -->|"trusted request"| FW
    W -->|"untrusted content"| FW
    FW -->|"content labeled trusted or untrusted"| A
    A -->|"proposed tool call"| FW
    FW -->|"allow"| T
    FW -->|"confirm"| U
    FW -.->|"block"| A
    T -->|"results (untrusted)"| FW

    classDef guard fill:#e8f0fe,stroke:#1a56c4,stroke-width:2px
    class FW guard
```

## Components

The modules of the `agentguard` package, the FastAPI proxy in front, and the optional Meta Model API behind the judge.

```mermaid
flowchart TB
    subgraph Clients["Clients"]
        AG["Agent framework"]
        AD["adapters: ToolGuard, OpenAI, Anthropic, LangChain"]
        DEMO["demo: SimAgent, LiveAgent, CLI, Streamlit"]
        BEN["bench: corpus and runner"]
    end

    subgraph API["agentguard.proxy (FastAPI)"]
        MW["Method filter, API key check, rate limit"]
        EP["Endpoints: sessions, ingest, model-output, authorize, audit, tools, health"]
    end

    subgraph Core["agentguard core"]
        FW["firewall.Firewall: sessions with idle expiry"]
        DET["detector: regex rules and zero-width check"]
        NRM["normalize: decoded readings of a text"]
        JDG["judge.MetaJudge (optional)"]
        TNT["taint.TaintTracker"]
        POL["policy.PolicyEngine: rules R1 to R5"]
        SCH["tool_schema: profiles and validation"]
        AUD["audit_store: hash-chained log"]
        RL["ratelimit and settings"]
        MOD["models"]
    end

    EXT["Meta Model API at api.meta.ai/v1"]
    LOG[("audit.jsonl")]

    AG -->|"HTTP"| MW
    MW --> EP
    MW --> RL
    EP --> FW
    AD -->|"in-process calls"| FW
    DEMO --> AD
    BEN --> FW
    FW --> DET
    FW --> JDG
    JDG -->|"POST /responses"| EXT
    FW --> TNT
    FW --> POL
    FW --> AUD
    AUD --> LOG
    TNT --> NRM
    POL --> TNT
    POL --> SCH
    FW --> MOD
```

## Request lifecycle

One run of the poisoned-page scenario. The page is ingested before the model sees it; each tool call is authorized before it runs.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant A as Agent
    participant FW as AgentGuard
    participant T as Tools
    participant J as Meta Model API

    U->>A: Summarize the page and email it to boss@acme.test
    A->>FW: new_session(request), source user, trusted
    A->>FW: authorize(fetch_page, report URL)
    FW-->>A: ALLOW (R0)
    A->>T: fetch_page(report URL)
    T-->>A: page text with a hidden instruction
    A->>FW: ingest(page, source tool:fetch_page)
    FW->>FW: detector.scan gives score and findings
    opt LLM judge enabled
        FW->>J: POST /responses with the untrusted text
        J-->>FW: JSON verdict (injection, confidence)
    end
    FW-->>A: item labeled untrusted, injection score
    A->>FW: authorize(read_file, ~/.ssh/id_rsa)
    FW-->>A: BLOCK (R1, path only named by the page)
    A->>FW: authorize(send_email, attacker@evil.test)
    FW-->>A: BLOCK (R1, address only named by the page)
    A->>FW: authorize(send_email, boss@acme.test)
    FW-->>A: CONFIRM (R4, context looks poisoned)
    A->>U: Approve sending the summary to boss@acme.test?
    U-->>A: Approved
    A->>T: send_email(boss@acme.test, summary)
```

## Policy decision flow

Rules are evaluated in order; the first match decides. Unknown tools fail closed.

```mermaid
flowchart TD
    S(["authorize(tool, args)"]) --> P["Look up tool profile (unknown tool = side-effect)"]
    P --> Q["Find target arguments and split them into user-authorized and not"]
    Q --> D1{"Risky tool and a target named only by untrusted content?"}
    D1 -->|"yes"| B1["BLOCK  R1"]
    D1 -->|"no"| D2{"Payload copies sensitive data to an unauthorized or unnamed target?"}
    D2 -->|"yes"| B2["BLOCK  R2"]
    D2 -->|"no"| D2b{"Arguments violate the declared schema?"}
    D2b -->|"yes"| B5["BLOCK  R5"]
    D2b -->|"no"| D3{"Risky tool and an unauthorized target?"}
    D3 -->|"yes"| C3["CONFIRM  R3"]
    D3 -->|"no"| D4{"Tool missing from the policy, or generated profile without a target?"}
    D4 -->|"yes"| C3b["CONFIRM  R3"]
    D4 -->|"no"| D5{"Risky tool and max injection score at or above 0.5?"}
    D5 -->|"yes"| C4["CONFIRM  R4"]
    D5 -->|"no"| A0["ALLOW  R0"]

    classDef deny fill:#fde2e2,stroke:#c0392b
    classDef ask fill:#fff3cd,stroke:#b9770e
    classDef ok fill:#d5f5e3,stroke:#1e8449
    class B1,B2,B5 deny
    class C3,C3b,C4 ask
    class A0 ok
```

## Data model

Core types: content items with trust labels and findings, decisions, audit events, sessions and the taint tracker.

```mermaid
classDiagram
    class Trust {
        <<enumeration>>
        TRUSTED
        UNTRUSTED
    }
    class Verdict {
        <<enumeration>>
        ALLOW
        CONFIRM
        BLOCK
    }
    class ToolRisk {
        <<enumeration>>
        READ
        SENSITIVE_READ
        SIDE_EFFECT
    }
    class Finding {
        +str rule_id
        +str description
        +float weight
        +str excerpt
    }
    class ContentItem {
        +int item_id
        +str text
        +str source
        +Trust trust
        +float injection_score
        +list~Finding~ findings
        +bool sensitive
        +list~int~ derived_from
    }
    class Decision {
        +Verdict verdict
        +str rule_id
        +str reason
        +str tool
        +dict args
        +list~str~ evidence
    }
    class AuditEvent {
        +float timestamp
        +str kind
        +str summary
        +dict detail
    }
    class ToolProfile {
        +ToolRisk risk
        +tuple target_args
    }
    class TaintTracker {
        +list~ContentItem~ items
        +is_user_authorized(value) bool
        +untrusted_origin(value) ContentItem
        +origins_of(text) list
        +exfiltrated_span(args) tuple
        +max_injection_score() float
    }
    class PolicyEngine {
        +evaluate(tool, args, tracker) Decision
    }
    class Session {
        +str session_id
        +TaintTracker tracker
        +list~AuditEvent~ events
        +list~Decision~ decisions
    }
    class Firewall {
        +new_session(prompt) str
        +ingest(session_id, text, source) ContentItem
        +authorize(session_id, tool, args) Decision
        +record_model_output(session_id, text) ModelOutputResult
        +audit(session_id) list
        +purge_expired() int
    }
    class AuditStore {
        +append(session_id, event) dict
        +verify(expected_head) VerifyResult
        +export(session_id) list
        +str head
    }
    class ToolSpec {
        +str name
        +dict parameters
    }
    class ToolGuard {
        +permit(tool, args)
        +run(tool, args, fn) any
        +protect(fn) callable
        +observe(tool, result)
        +model_said(text)
    }

    ContentItem --> Trust
    ContentItem "1" o-- "*" Finding
    Decision --> Verdict
    ToolProfile --> ToolRisk
    TaintTracker "1" o-- "*" ContentItem
    Session *-- TaintTracker
    Session o-- AuditEvent
    Session o-- Decision
    Firewall "1" o-- "*" Session
    Firewall --> PolicyEngine
    PolicyEngine ..> TaintTracker : reads
    PolicyEngine ..> ToolProfile : looks up
    PolicyEngine ..> Decision : returns
    PolicyEngine ..> ToolSpec : validates calls against
    Firewall o-- AuditStore
    ToolGuard --> Firewall : wraps
```

## Deployment modes

Use the firewall in-process as a library, or run it as an HTTP service in front of the agent.

```mermaid
flowchart LR
    subgraph Host["Agent host"]
        AG["Agent runtime (LLM and tool loop)"]
        LIB["Option A: ToolGuard or Firewall in-process"]
    end

    subgraph Svc["Option B: AgentGuard service"]
        UV["uvicorn agentguard.proxy:app with API key and rate limit"]
        FWS["Firewall and sessions in memory, idle expiry"]
        LOG[("hash-chained audit file")]
    end

    EXT["Meta Model API, key from MODEL_API_KEY"]
    TOOLS["Real tools: browser, mail, filesystem"]

    AG -->|"direct calls"| LIB
    AG -->|"HTTP GET and POST"| UV
    UV --> FWS
    FWS --> LOG
    FWS -->|"only untrusted, non-sensitive content"| EXT
    AG -->|"after allow or approved confirm"| TOOLS
```

## Attack chain and defensive layers

Detection raises suspicion early; taint tracking and the policy rules act at the tool call, the one point the attacker cannot avoid.

```mermaid
flowchart LR
    A1["Attacker plants text in a page"] --> A2["Agent fetches the page"]
    A2 --> A3["Model follows the hidden instruction"]
    A3 --> A4["Tool call aimed at an attacker target"]
    A4 --> A5["Data leaves the machine"]

    D1["Detector and LLM judge raise suspicion"] -.->|"cuts here"| A2
    D2["Taint tracking and rules R1, R2 block the call"] -.->|"cuts here"| A4
    D3["Rules R3, R4 ask a human"] -.->|"cuts here"| A4

    classDef atk fill:#fde2e2,stroke:#c0392b
    classDef def fill:#e8f0fe,stroke:#1a56c4
    class A1,A2,A3,A4,A5 atk
    class D1,D2,D3 def
```

## Agent loop with ToolGuard

What happens on each tool call when an agent loop uses `agentguard.adapters.ToolGuard`.

```mermaid
sequenceDiagram
    participant M as Model
    participant G as ToolGuard
    participant F as Firewall
    participant T as Tool

    M->>G: assistant text
    G->>F: record_model_output(text)
    M->>G: tool call (name, args)
    G->>F: authorize(name, args)
    alt BLOCK
        F-->>G: BLOCK (rule, reason)
        G-->>M: refusal text, the tool never runs
    else CONFIRM and the user declines
        F-->>G: CONFIRM (rule, reason)
        G-->>M: not run, the user did not approve
    else ALLOW, or CONFIRM approved
        G->>T: run(args)
        T-->>G: result
        G->>F: ingest(result, source tool:name)
        G-->>M: result
    end
```
