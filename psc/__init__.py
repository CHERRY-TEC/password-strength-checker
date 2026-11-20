"""Password Strength Checker (PSC) package.

A zero-dependency, beginner-friendly Python application that evaluates password
characteristics locally and explains basic strength rules.

IMPORTANT DESIGN NOTE:
    This application NEVER stores the passwords it checks. Only the derived
    analysis metadata (score, rating, characteristics, timestamp and an
    optional user supplied label) is persisted so that records survive
    program restarts.
"""

from .config import APP_NAME, APP_VERSION

__all__ = ["APP_NAME", "APP_VERSION"]
