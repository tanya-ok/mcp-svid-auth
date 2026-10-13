"""Fixed loopback profiles for the local synthetic identity demonstration."""

from __future__ import annotations

import os

_PROFILE = os.environ.get("SVID_IDENTITY_PROFILE", "default")
if _PROFILE not in {"default", "isolated"}:
    raise ValueError("Invalid local identity profile")
ISOLATED = _PROFILE == "isolated"
VIEWER_PORT = 4566 if ISOLATED else 4466
IDENTITY_PORT = 4567 if ISOLATED else 4467
LOGIN_PORT = 4568 if ISOLATED else 4468
VIEWER_TUNNEL_PORT = 14566 if ISOLATED else 14466
IDENTITY_TUNNEL_PORT = 14567 if ISOLATED else 14467
LOGIN_TUNNEL_PORT = 14568 if ISOLATED else 14468
NAMESPACE = "security-lab-passkey" if ISOLATED else "security-lab-identity"
UNIT_PREFIX = "security-lab-passkey" if ISOLATED else "security-lab-identity"
