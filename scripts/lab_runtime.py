"""Shared safe errors and runtime-neutral Kubernetes service inventory."""

from pathlib import Path
from typing import Any

import yaml


class DemoRuntimeError(Exception):
    """Fixed operator-facing error; captured output must never be included."""


SERVICES: dict[str, Any] = yaml.safe_load(
    (Path(__file__).resolve().parent.parent / "deploy/kubernetes/services.yaml").read_text()
)["services"]
