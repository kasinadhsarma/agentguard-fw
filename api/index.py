"""Vercel entry point: serves the demo web interface as a serverless function.

Not tested on Vercel from the authors' sandbox. Locally the same handler is
served by `python3 -m demo.web`.
"""

from demo.web import Handler


class handler(Handler):  # noqa: N801  (Vercel looks for this exact name)
    """Same routes as the local demo server."""
