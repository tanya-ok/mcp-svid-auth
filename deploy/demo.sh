#!/usr/bin/env bash
# Brings up SPIRE, registers workloads, starts authz and two notes servers, runs the scenarios.
set -euo pipefail
cd "$(dirname "$0")"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running. Start it and re-run." >&2
  exit 1
fi

A="http://notes-a:8101/mcp"
B="http://notes-b:8102/mcp"
server() { docker compose exec -T spire-server /opt/spire/bin/spire-server "$@"; }

mkdir -p .data
echo "== SPIRE server"
docker compose up -d --wait spire-server
server bundle show > .data/bundle.pem
JOIN_TOKEN="$(server token generate -spiffeID spiffe://example.org/node/agent -ttl 600 | awk '/Token:/ {print $2}')"
export JOIN_TOKEN

echo "== SPIRE agent"
docker compose up -d spire-agent
./register.sh
echo "waiting for the agent to sync entries"
sleep 8

echo "== authz and MCP servers"
docker compose up -d --build authz notes-a notes-b
sleep 3

run() { docker compose run --rm --no-deps "$@" || true; }

echo
echo "== 1. research agent on notes-a: read and write allowed"
run agent-research --resource "$A" --scope "notes:read notes:write" \
  --spiffe-id spiffe://example.org/agent/research

echo
echo "== 2. research agent on notes-b: read allowed, write denied by scope (403)"
run agent-research --resource "$B" --scope notes:read

echo
echo "== 3. intruder: valid SVID, not allowlisted, no token"
run agent-intruder --resource "$A" --scope notes:read

echo
echo "== 4. replay: token issued for notes-a sent to notes-b (401, wrong audience)"
run agent-research --resource "$A" --scope "notes:read notes:write" --steal-token "$B"

echo
echo "== audit lines"
docker compose logs --no-log-prefix authz notes-a notes-b | grep '"decision"' || true

echo
echo "Tear down with: docker compose -f deploy/docker-compose.yml down -v"
