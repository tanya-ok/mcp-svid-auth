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
AUTHZ="http://authz:8100"
server() { docker compose exec -T spire-server /opt/spire/bin/spire-server "$@"; }

mkdir -p .data/policy
cp policy.yaml .data/policy/policy.yaml
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

# Compose service names resolve to private addresses and speak plain http, so the agents run
# with the dev flags that relax the URL checks.
run() {
  local agent="$1"
  shift
  docker compose run --rm --no-deps "$agent" --trusted-issuer "$AUTHZ" \
    --allow-http --allow-private-network "$@" || true
}

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
echo "== 5. impostor: another container with the agent-research label gets agent/research"
run agent-impostor --resource "$A" --scope notes:read --call 'notes.search={"query":"welcome"}'

echo
echo "== 6. malicious PRM: notes-rogue names an untrusted authorization server (issuer_refused)"
docker compose --profile scenarios up -d notes-rogue
sleep 2
run agent-research --resource http://notes-rogue:8103/mcp --scope notes:read

echo
echo "== 7. SVID replay: one JWT-SVID posted to /token twice"
docker compose run --rm --no-deps -T --entrypoint python agent-research - <<'PY' || true
import json

import httpx2
from spiffe import WorkloadApiClient

client = WorkloadApiClient()
svid = client.fetch_jwt_svid(audience={"http://authz:8100"}).token
client.close()
form = {
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
    "client_assertion": svid,
    "resource": "http://notes-a:8101/mcp",
    "scope": "notes:read",
}
for attempt in (1, 2):
    response = httpx2.post("http://authz:8100/token", data=form)
    body = response.json()
    print(json.dumps({"event": "svid_replay", "attempt": attempt, "status": response.status_code,
                      "error": body.get("error"), "token_issued": "access_token" in body}))
PY

echo
echo "== 8. upstream call: notes-a calls notes-b with its own token, never the caller's"
run agent-research --resource "$A" --scope notes:read \
  --call 'notes.search_upstream={"query":"welcome"}'
docker compose logs --no-log-prefix notes-b | grep '"spiffe://example.org/mcp/notes-a"' | tail -1 || true

echo
echo "== 9. grant revocation: remove agent/research's notes-b grant while authz runs"
run agent-research --resource "$B" --scope notes:read --call 'notes.search={"query":"welcome"}'
cat > .data/policy/policy.yaml <<'YAML'
trust_domain: example.org
clients:
  - spiffe_id: spiffe://example.org/agent/research
    resources:
      http://notes-a:8101/mcp: [notes:read, notes:write]
  - spiffe_id: spiffe://example.org/mcp/notes-a
    resources:
      http://notes-b:8102/mcp: [notes:read]
YAML
echo "policy edited at $(date -u +%H:%M:%S) UTC"
sleep 7
run agent-research --resource "$B" --scope notes:read --call 'notes.search={"query":"welcome"}'
docker compose logs --no-log-prefix authz | grep '"policy_reload"' | tail -1 || true
cp policy.yaml .data/policy/policy.yaml
sleep 7

echo
echo "== 11. authz restart: new signing key while notes-a caches the old JWKS"
docker compose restart authz
sleep 3
run agent-research --resource "$A" --scope notes:read --call 'notes.search={"query":"welcome"}'

echo
echo "== audit lines"
docker compose logs --no-log-prefix authz notes-a notes-b notes-rogue | grep '"decision"' || true

echo
echo "== audit hash chain of notes-a and notes-b (stderr, one chain per process)"
for svc in notes-a notes-b; do
  docker compose logs --no-log-prefix "$svc" | grep '^{"record_id"' |
    docker compose run --rm --no-deps -T --entrypoint mcp-svid-audit-verify agent-research /dev/stdin |
    sed "s|^/dev/stdin|$svc|" || true
done

echo
echo "Tear down with: make down"
