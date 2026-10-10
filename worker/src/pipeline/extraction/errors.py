"""Errors raised by the extraction layer."""

from __future__ import annotations


class InvalidApkError(Exception):
    """The file is not an APK we are willing or able to analyse.

    ``reason`` is a short human-readable sentence that is safe to show to a user.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
