#!/usr/bin/env bash
# Registration entries. Selectors are unix UIDs, matching `user:` in docker-compose.yml.
set -euo pipefail
cd "$(dirname "$0")"

PARENT="spiffe://example.org/node/agent"

entry() {
  local spiffe_id="$1" uid="$2"
  docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
    -parentID "$PARENT" -spiffeID "$spiffe_id" -selector "unix:uid:$uid" -jwtSVIDTTL 300 >/dev/null
  echo "registered $spiffe_id (unix:uid:$uid)"
}

entry spiffe://example.org/authz 1010
entry spiffe://example.org/mcp/notes-a 1011
entry spiffe://example.org/mcp/notes-b 1012
entry spiffe://example.org/agent/research 1001
entry spiffe://example.org/agent/intruder 1002
