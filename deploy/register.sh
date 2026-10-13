#!/usr/bin/env bash
# Registration is normally performed by make demo in the dedicated CNCF VM.
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run --locked python -m scripts.kubernetes_demo register
