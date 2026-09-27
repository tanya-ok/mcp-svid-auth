#!/usr/bin/env bash
# Registration entries. Selectors are docker labels, matching `labels:` in docker-compose.yml.
set -euo pipefail
cd "$(dirname "$0")"

PARENT="spiffe://example.org/node/agent"
LABEL="org.example.svid.workload"

# -jwtSVIDIncludeJTI (SPIRE 1.15+): each JWT-SVID gets a fresh random jti and the agent JWT-SVID
# cache is bypassed. authz accepts each (sub, jti) once, so a cached SVID would be refused on reuse.
entry() {
  local spiffe_id="$1" workload="$2"
  docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
    -parentID "$PARENT" -spiffeID "$spiffe_id" -selector "docker:label:$LABEL:$workload" \
    -jwtSVIDTTL 300 -jwtSVIDIncludeJTI >/dev/null
  echo "registered $spiffe_id (docker:label:$LABEL:$workload)"
}

entry spiffe://example.org/authz authz
entry spiffe://example.org/mcp/notes-a notes-a
entry spiffe://example.org/mcp/notes-b notes-b
entry spiffe://example.org/agent/research agent-research
entry spiffe://example.org/agent/intruder agent-intruder
