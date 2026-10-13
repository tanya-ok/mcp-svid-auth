# Cost budgets and planned signing rotation

These changes implement `svid-xoz`. They preserve single-resource ES256 `at+jwt`
tokens and runtime-generated private keys. No credential is persisted or exposed
by an administrative rotation endpoint.

## Planned rotation

`--signing-rotation-seconds` defaults to 3600, accepts zero to disable and otherwise
requires at least 60. The next public key is published for 60 seconds before it
signs anything, matching this project's resource JWKS cache. Preparation starts
on a JWKS or token request after the interval; activation happens on a later
request after the publication window. Idle issuers do not skip prepublication.

The previous public key stays until the latest expiry issued with it plus at
least the SVID clock-skew margin. Retirement uses wall time so clock rollback
does not prematurely discard a still-valid token's key. Scheduling uses monotonic
time. At most six retired public keys are retained; a full retired set defers
further preparation. Private retired keys are discarded on activation. JWKS
contains only public material. All signing/context changes share a lock so a
concurrent token cannot be signed with one key and labeled with another key ID.

An abrupt process restart still loses the old key set and replay state. This is
planned in-process rotation, not HA or restart-safe key persistence. Other resource
implementations must coordinate their own cache lifetimes with prepublication.
The lab sets a 60-second interval to exercise an actual planned transition after
its existing restart check; production defaults remain 3600 seconds.

## Request cost

| Boundary | Default behavior |
|---|---|
| Token endpoint | 50 requests per process per fixed one-second window, before form parsing/signature verification |
| Authorized subject | 10 exchanges per verified, policy-authorized subject per one-second window, including SVID reuse mode |
| Token form | URL-encoded UTF-8 only; 16384 URL-encoded body bytes, at most 16 fields; repeated names denied |
| Replay cache | 10000 live entries globally, 1000 per verified subject; no live-entry eviction |
| Resource token verifier | 256 admissions per process per second; ASCII token at most 8192 bytes; ES256/type/key-ID checks before JWKS access |
| JWKS fetch | At most one attempt per 10 seconds during cold/expired outages and unknown-key refresh; expired keys are never a fallback |
| JWKS response | At most 65536 decoded bytes and 16 keys; fixed issuer URI, no redirects |

Token and subject budgets return fixed 429 errors with `Retry-After: 1` and no-store
headers. The resource verifier returns authentication denial when its budget is
exhausted and records `verification_budget_exceeded`; it does not expose private
exception text. Global traffic can still deny service to legitimate callers.
A fixed window allows bursts on both sides of a boundary. An upstream gateway
must enforce connection, bandwidth and distributed abuse limits separately.
Audit writing still costs work for refused calls and requires operational limits.

The cache counts only requests authorized for a resource/scope. Subject counters
are removed as assertions expire. `--replay-cache-size` and
`--replay-subject-limit` configure the memory quotas; token and subject rate flags
configure issuance rates. Choose a global cache large enough for the aggregate
accepted unique-assertion rate times maximum assertion lifetime plus skew, and a
subject quota smaller than the global cap to preserve capacity for other callers.
Several authorized callers can still fill the global bound. Reload and replicas
do not provide distributed fairness or persistent replay protection.

## Evidence

Tests exercise real signed synthetic assertions, per-subject and global refusal,
expiry cleanup, unauthorized-request non-allocation, atomic window counters,
streaming size/field limits, cold-outage fetch storms, response bounds, and old/new
token validation through the real ASGI issuer and cached resource verifier. A
bounded live probe fetches three real SPIRE assertions and reports only distinct
counts and presence of `jti`, then verifies one at the token endpoint. It does not
assume a caller can choose or multiply signed `jti` values. A separate live probe
requires public prepublication and both old/new MCP calls during actual rotation.
The shared lab passed all 18 scenarios on 2026-10-07 after a fresh image rebuild.
Three real SPIRE fetches returned one distinct assertion and one distinct `jti`;
the assertion was accepted. Public prepublication, old/new public-key overlap and
both MCP token calls passed during planned rotation. Scoped teardown passed and
the pre-existing CISO namespace UID was unchanged; the shared VM remained running.
The 525-test offline suite, strict docs build, identifier scan and source/history
secret scans passed. The secret scanner excludes one exact historical finding
verified against the review packet SHA-256; no credential or general rule is excluded.

## Invariant review

- Deny by default: policy checks precede replay allocation; scope/tool rules are unchanged.
- Audience binding: issue/verify still require one canonical resource; existing audience tests remain mandatory.
- No passthrough: the relay still obtains its own credential; existing relay tests remain mandatory.
- Strict token checks: ES256, `at+jwt`, required issuer/audience/times remain enforced before tool dispatch.
- No secrets in output: all new denial descriptions are fixed; JWKS exposes only runtime public keys.
- Fail closed: quota, missing credentials and expired JWKS deny; no stale-key or cached-SVID grace is added.
- Runtime keys: pending keys are generated in memory; no private key or real bundle is committed.
