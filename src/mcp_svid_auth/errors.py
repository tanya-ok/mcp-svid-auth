"""Shared error type carrying an OAuth error code."""

from __future__ import annotations


class AuthError(Exception):
    """An authentication or authorization failure with an RFC 6749 style error code.

    `description` goes to the client and must be a fixed, generic string.
    `detail` goes to the audit log only.
    """

    def __init__(self, code: str, description: str, status: int = 400, detail: str = "") -> None:
        super().__init__(description)
        self.code = code
        self.description = description
        self.status = status
        self.detail = detail
