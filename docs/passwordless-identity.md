# Passwordless human identity

This is a local proof of concept, reviewed against ZITADEL 4.19.4 on
2026-10-06. The implementation was verified in a separate worktree and transferred
to the main local lab, where eleven WebAuthn/OIDC checks and the complete scoped
lifecycle passed after an operator-approved VM restart. No Google account has
been connected and no personal passkey has been enrolled.

## Intended sign-in

An administrator approves a verified Google identity and creates its ZITADEL
account without a password. Account linking uses Google's stable `sub` and
provider ID, not a mutable email address. The initial verified email is an
approval input; the application's roster contains stable ZITADEL subjects.
The user then enrolls a WebAuthn passkey with required user verification.
Only the approved subject with a signed viewer role can access the panel.

A passkey proves possession of a private key and unlocks it locally with a
PIN or biometric check. The server receives a signature, not the private key,
PIN or fingerprint. WebAuthn binds the credential to the site's relying-party
ID and checks its origin. The credential does not work on a phishing site's
unrelated domain. A verified passkey supplies MFA without an additional SMS
or one-time code. A key that merely detects touch is insufficient here.

ZITADEL and Google authentication are separate. The Google button alone does
not prove a passkey was used. ZITADEL cannot remove password or recovery options
from a consumer Google account. This design requires its own verified WebAuthn
factor even after Google authentication; Google account recovery must not
recover or replace that factor automatically.

## Two explicit profiles

The implemented synthetic profile exercises native ZITADEL passkeys. It enables
local authentication, disables external IdPs, creates users without passwords,
closes self-registration and permits only the verified WebAuthn multi-factor.
The provider's effective organization policy is checked after provisioning and
before reuse. The acceptance runner also reads back the policy before testing.

The planned Google profile uses `google_webauthn_login_settings()` and closed
provider options in `scripts/passwordless_policy.py`:

| Setting | Required value |
|---|---|
| Local authentication | Disabled |
| External IdP | Enabled, only the approved Google provider |
| Self-registration and domain discovery | Disabled |
| Force MFA | Enabled for external authentication as well |
| Force MFA local only | Disabled |
| Second factors | Empty; no touch-only U2F, SMS, email OTP or TOTP |
| Multi factors | U2F with verification only |
| Passkeys | Allowed |
| Password reset interface and phone login | Hidden/disabled |
| Authentication factor lifetimes | Five minutes |
| MFA setup skip lifetime | Zero |
| Provider account creation, self-linking and automatic linking | Disabled |

In this release `allowUsernamePassword` is the deprecated name for local
authentication, including standalone passkeys. Turning it off also prevents
native passkey-only sign-in. The Google profile therefore authenticates through
Google first and requires verified WebAuthn afterward. The native synthetic
profile needs local authentication enabled. Neither profile permits password
or OTP evidence at the application gate. ZITADEL exposes passkeys as allowed
or not allowed, without a passkey-required policy enum.

The Management v1 policy writer uses `allowUsernamePassword` and
`passwordlessType`; the Settings v2 API uses `allowLocalAuthentication` and
`passkeysType`. These names must be translated explicitly. Omitted protobuf
false booleans and empty factor lists mean their protocol defaults; required
true settings, enum values and durations are still checked strictly.

## Application checks

After signature, issuer, audience, expiry and nonce validation, the gate checks:

- The exact ZITADEL subject is in the administrator's approval roster.
- The viewer role belongs to the configured organization.
- Signed `amr` is exactly `user` and `mfa`, with no password, OTP or extra method.
- Signed `auth_time` is an integer no more than five minutes old and not future-dated.

ZITADEL 4.19.4 maps verified native passkeys and external-IdP plus U2F to the
same `user,mfa` values. AMR alone cannot prove user verification or which IdP
was used. The effective policy, required WebAuthn challenge and provider links
are necessary parts of the design. Production operation must monitor policy
and factor changes and invalidate sessions when approval is revoked; the demo
keeps its approval roster in memory until restart and bounds sessions to five
minutes.

The OIDC request selects the application's organization, requests fresh login,
and uses Authorization Code with S256 PKCE, one-use state and nonce. Only an
opaque HttpOnly session reaches the browser. Provider and Kubernetes tokens
remain separate. Human approval grants no workload, MCP tool or clinical record
permissions.

## Private Google inputs

For the main checkout, create the private blank template with
`make google-config-init`, fill it locally, and run `make google-config-check`.
Use `SVID_IDENTITY_PROFILE=isolated` for the separate test profile. The ignored
file is `deploy/.data/google-onboarding.json` in default mode, or
`deploy/.data/passkey/google-onboarding.json` in isolated mode. Creation uses
mode 0600 and refuses to overwrite an existing file.

Fill only `approved_emails`, `oauth_client_id` and `oauth_client_secret`; never
paste the secret into chat. An empty template intentionally fails validation.
The checker rejects duplicate JSON keys, symlinks, non-regular files, wrong
ownership, oversized input and access by another user. Its output includes only
the account count, callback and fixed closed options, never addresses, client
ID or secret. Validation does not provision users, link identities or grant
access.

`make google-setup-demo` exercises the ZITADEL policy/provider APIs with a
temporary organization, fake random secret and no users. It verifies the
organization owner, closed creation and linking options, and the single active
Google provider. It does not contact Google or verify real OAuth credentials.
Its safe report explicitly records `google_contacted: false` and
`google_login_verified: false`. The main profile passed four setup checks on
2026-10-06. Two consecutive runs also preserved the active viewer's private
session and tunnel. Setup verifies the owned viewer capability before borrowing
that connection; an unverifiable listener is refused. Without a viewer, setup
owns and closes its temporary connection. Each fixture uses a unique empty
organization, removed with the ephemeral identity namespace by `make down`.

## Connect an approved Google account

The following are pending operator steps, not completed integration:

1. Supply the Gmail address to approve. Create an OAuth Web application in the
   chosen Google Cloud project. Copy the callback shown by the ZITADEL Google
   template into its authorized redirect URI. For the local default profile
   this is `http://localhost:4467/idps/callback`; isolated mode uses port 4567.
2. Fill the three private fields above, or use a proper secret store for a
   deployed system. Do not paste the secret into chat, commit it or put it in
   command arguments.
   Configure scopes `openid`, `profile`, `email`; no Gmail mailbox access is needed.
3. Before enabling Google, add a reviewed outbound HTTPS path from ZITADEL to
   the endpoints in Google's verified OpenID discovery document. The synthetic
   lab policy currently permits only local namespace traffic and DNS, so it
   cannot complete a Google exchange. Use a constrained egress proxy or an
   appropriate domain-aware policy; do not silently open unrestricted egress.
4. Create and activate an organization-scoped Google provider. Close account
   creation, self-linking, automatic creation and email-based auto-linking.
   Only existing administrator-approved links may be used. The closed provider
   behavior still needs an actual Google acceptance test in this version.
5. Use a controlled enrollment flow that cryptographically validates Google's
   issuer, audience, signature, state/nonce, `email_verified` and stable `sub`.
   Check the verified email against the approval pool before creating the user
   and provider link. Never mark a real email verified from user-entered text or
   use an unverified decoded token as identity proof.
6. Enroll two verified passkeys while the user is physically present, for
   example their device and a separately stored hardware key. Keep the account
   unapproved and without a viewer grant until enrollment is verified.
7. Grant the viewer role and approve the stable ZITADEL subject. Apply the Google
   policy, read it back, and prove that unapproved Gmail accounts, a Google-only
   session, passwords, OTP and a key without verification are denied.

Do not enable email auto-linking to simplify enrollment. Google OAuth test-user
lists can help limit a demo, but they do not replace the application's approval
roster. Changing an email address must not silently replace an identity link.

## Recovery and administrator access

The first recovery method is a second enrolled passkey stored separately.
A synced passkey may provide an additional device path, but its cloud account's
recovery rules remain part of that trust boundary. Prefer a separate hardware
key for administrator and break-glass access.

If every key is lost, a separate administrator verifies identity through an
agreed process, suspends access, revokes old credentials and sessions, and
supervises new key enrollment. Record the approval and the change in the audit
trail. Mail and SMS can carry notifications; they cannot replace the passkey
or act as the sole recovery proof in this design. The demo implements no
self-service recovery endpoint.

Keep administrator identities in a separate organization, with at least two
verified authenticators and a tested backup administrator. The local bootstrap
owner PAT has broad privileges and expires after two days; Login V2 uses a
separate login-client identity. Runtime bootstrap credentials are lab setup
material, not end-user sign-in methods. Production administrator hardening and
offline break-glass storage require their own verified deployment.

## Verification on 2026-10-06

| Check | Current evidence |
|---|---|
| Separate source offline gate | Passed: 445 tests, lint, formatting, strict types and generated configuration; strict documentation build passed |
| Transferred root offline gate | Passed: 467 tests, including protection of foreign namespaces, safe observations, isolated panel restrictions, strict mTLS probe cases, host audit loading, private-umask image builds and closed Google inputs/provider readback and setup lifecycle; strict docs and source/history secret scans passed |
| Closed local policy | Read back from real ZITADEL: no registration, no external IdP, verified WebAuthn only |
| New native WebAuthn/OIDC acceptance | Passed all eleven checks in the main profile: registration, verified passkey/PKCE, unverified-key and cross-challenge replay denial, opaque session, read-only access, callback replay denial, logout and unapproved-user denial |
| Isolated identity teardown | Passed: own namespace, accounts/profile/session files and five loopback listeners removed; shared VM retained |
| Closed Google setup | Passed four main-profile checks against real ZITADEL policy/provider APIs, using a fake random secret and no accounts; two repeated runs preserved the viewer. Google was not contacted and its login is unverified |
| Legacy main profile fails closed | Passed in the main checkout: panel startup exits non-zero with a fixed error, ports 4466 and 4467 stay closed, and pod identities in the core, identity and CISO namespaces remain unchanged |
| Google login and required verified passkey | Pending OAuth configuration, constrained HTTPS egress, approved Gmail identity and physical enrollment |
| Fresh workload regression | Eighteen scenarios passed after a fresh rebuild in the recovery cycle from 15:25 to 15:31 UTC. A prior enabled-profile repeat passed eighteen at 15:02 UTC, using fresh relay credential and FHIR audit state |
| Main interface | Five protected desktop views, actual browser logout and 390 x 844 mobile layout with visible Refresh passed. The hosted Login V2 form reached required passkey authentication without a password form. Physical completion is unverified |
| Main integration lifecycle | Passed by 15:31 UTC: viewer stop, idempotent restart, identity-backend-loss shutdown, recovery and both scoped teardowns. Three owned namespaces, private identity records and five listeners were removed; CISO's namespace UID and the running VM were preserved |
| Startup memory | Sixty-four samples at five-second intervals across the recovery cycle including native-profile startup observed a maximum of 1858.1 MiB (`MemTotal - MemAvailable`), no measurement failures; guest only, with a 4 GiB cap |
| Recovery and backup keys | Operator procedure specified; not yet rehearsed with a real account |

The operator approved deletion of the legacy ephemeral identity database on
2026-10-06. Its replacement passed the main native identity checks. The earlier
failed-start check proved that the panel refused the old profile without
falling back to anonymous access or treating a password as verified WebAuthn.
That check did not remove or restart any pods. Its safe local evidence is in the ignored
`deploy/.data/legacy-profile-fail-closed-report.json`.

A prior final cycle failed after macOS disk exhaustion and guest I/O errors.
The operator-approved VM restart restored guest access. The complete fresh
cycle then passed, including identity acceptance, mobile rendering and final
cleanup. Recovery retained CISO's namespace identity and its version 0.1.1
readiness endpoint was independently checked.

The acceptance runner requires Node.js, Playwright 1.x and its Chromium browser
or an installed compatible Chrome. Existing test installations can supply
`PLAYWRIGHT_NODE_PATH`, `PLAYWRIGHT_MODULE_PATH` and `PLAYWRIGHT_CHROME_PATH`.
These are test dependencies, separate from the Kubernetes runtime. No test
browser is needed for the base eighteen workload scenarios.

The runner uses the private Session API to complete OIDC after browser WebAuthn
checks. It does not prove every screen of the hosted Login V2 form. The test
browser uses an ephemeral virtual CTAP2 authenticator. Its private keys
stay in browser memory and are never exported. Even a successful synthetic run
would not prove a person's Face ID, hardware key or Google recovery setup.
The acceptance script also proved that the server rejects a deliberately
downgraded browser assertion whose signed user-verification flag is false,
and rejects a signed assertion replayed against a new server challenge.
ZITADEL returned HTTP 500 with RPC INTERNAL for these validation failures.
A successful verified check immediately afterward proved the provider was
available; the test did not count a timeout or generic outage as a denial. The test helper has bounded waits and fixed failure messages. Results contain
only safe verdict labels and a timestamp.

## Primary references

- [ZITADEL 4.19.4 release](https://github.com/zitadel/zitadel/releases/tag/v4.19.4)
- [ZITADEL login and MFA settings](https://zitadel.com/docs/guides/manage/console/default-settings)
- [ZITADEL Google provider](https://zitadel.com/docs/guides/integrate/identity-providers/google)
- [ZITADEL passkey integration](https://zitadel.com/docs/guides/integrate/login-ui/passkey)
- [ZITADEL administrator hardening](https://zitadel.com/docs/guides/manage/console/administrator-hardening)
- [ZITADEL AMR mapping at the pinned version](https://github.com/zitadel/zitadel/blob/v4.19.4/internal/api/oidc/amr.go)
- [ZITADEL MFA enforcement at the pinned version](https://github.com/zitadel/zitadel/blob/v4.19.4/apps/login/src/lib/mfa-helper.ts)
- [Google OpenID Connect claims and identity validation](https://developers.google.com/identity/openid-connect/openid-connect)
