"""Vercel entry point: serves the demo web interface as a serverless function.

Vercel's rewrite hands every request to this function with the path
/api/index and the original route in the query string (see vercel.json),
so this class maps it back to the routes demo.web already serves. Locally
the same routes are served by `python3 -m demo.web`.
"""

from urllib.parse import parse_qs, urlparse

from demo.web import Handler

ROUTES = {'': '/', 'scenarios': '/api/scenarios', 'run': '/api/run'}


class handler(Handler):  # noqa: N801  (Vercel looks for this exact name)
    """Same routes as the local demo server, behind Vercel's rewrites."""

    def _restore_path(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.rstrip('/') == '/api/index':
            op = parse_qs(parsed.query).get('op', [''])[0]
            self.path = ROUTES.get(op, '/missing')

    def do_GET(self) -> None:  # noqa: N802
        """Serve the page or the scenario list."""
        self._restore_path()
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        """Run a scenario."""
        self._restore_path()
        super().do_POST()
