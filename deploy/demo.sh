#!/usr/bin/env bash
# Entry point for the Lima/Kubernetes/containerd demo.
set -euo pipefail
cd "$(dirname "$0")/.."
exec make demo
