"""Local web interface for the Password Strength Checker.

Serves a single-page frontend backed by the same Python analysis engine used
by the console application.  No third-party packages are required.

``serve`` is resolved lazily so ``python -m webui.server`` does not emit a
runpy re-import warning.
"""

from typing import Any

__all__ = ["serve"]


def __getattr__(name: str) -> Any:
    if name == "serve":
        from .server import serve

        return serve
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
