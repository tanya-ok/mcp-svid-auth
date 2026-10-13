import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  fetchIssuerKeys,
  requireToolScopes,
  verifyAccessToken,
} from "../deploy/kubernetes/token-verifier.mjs";

test("public key fetch forwards no incoming credential and refuses redirects", async () => {
  let captured;
  const keys = await fetchIssuerKeys(
    "http://authz:8100",
    async (url, options) => {
      captured = { url, options };
      return new Response(JSON.stringify({ keys: [] }));
    },
  );
  assert.deepEqual(keys, { keys: [] });
  assert.equal(captured.url, "http://authz:8100/jwks.json");
  assert.equal(captured.options.redirect, "error");
  assert.equal(
    new Headers(captured.options.headers).has("authorization"),
    false,
  );
  await assert.rejects(
    fetchIssuerKeys(
      "http://authz:8100",
      async () => new Response("{}", { status: 500 }),
    ),
  );
});

test("unscoped or duplicate tools stop startup", () => {
  requireToolScopes(["read"], { read: "fhir:read" });
  assert.throws(() =>
    requireToolScopes(["read", "undeclared"], { read: "fhir:read" }),
  );
  assert.throws(() =>
    requireToolScopes(["read", "read"], { read: "fhir:read" }),
  );
  assert.throws(() => requireToolScopes(["read"], { read: "fhir:write" }));
});

const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});
const jwks = {
  keys: [
    {
      ...publicKey.export({ format: "jwk" }),
      kid: "runtime-test-key",
      alg: "ES256",
      use: "sig",
    },
  ],
};
const options = {
  issuer: "http://authz:8100",
  resource: "https://fhir.security-lab.svc.cluster.local:8443/mcp",
  caller: "spiffe://example.org/agent/research",
  now: 1000,
};
const claims = {
  iss: options.issuer,
  aud: options.resource,
  sub: options.caller,
  iat: 999,
  exp: 1299,
  scope: "fhir:read",
};
function token(
  body = claims,
  header = { typ: "at+jwt", alg: "ES256", kid: "runtime-test-key" },
) {
  const encoded = [header, body]
    .map((value) => Buffer.from(JSON.stringify(value)).toString("base64url"))
    .join(".");
  return `${encoded}.${sign("sha256", Buffer.from(encoded), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}
test("accepts a signed token bound to the mTLS caller and one resource", () =>
  assert.equal(verifyAccessToken(token(), jwks, options).sub, options.caller));
for (const [name, change] of Object.entries({
  "other audience": { aud: "http://notes-a:8101/mcp" },
  "audience array": { aud: [options.resource] },
  "another peer": { sub: "spiffe://example.org/agent/intruder" },
  "another issuer": { iss: "http://untrusted.example.org" },
  expired: { exp: 1000 },
  "future issued-at": { iat: 1001 },
  "future not-before": { nbf: 1001 },
  "missing expiry": { exp: undefined },
  "missing issued-at": { iat: undefined },
  "extended lifetime": { exp: 1300 },
  "missing scope": { scope: "" },
}))
  test(`rejects ${name}`, () =>
    assert.throws(() =>
      verifyAccessToken(token({ ...claims, ...change }), jwks, options),
    ));
for (const [name, change] of Object.entries({
  algorithm: { alg: "HS256" },
  type: { typ: "JWT" },
  critical: { crit: ["b64"] },
  embeddedKey: { jwk: jwks.keys[0] },
  remoteKey: { jku: "https://untrusted.example.org/jwks" },
  keyId: { kid: "unknown" },
}))
  test(`rejects changed header ${name}`, () =>
    assert.throws(() =>
      verifyAccessToken(
        token(claims, {
          typ: "at+jwt",
          alg: "ES256",
          kid: "runtime-test-key",
          ...change,
        }),
        jwks,
        options,
      ),
    ));
test("rejects forged and ambiguous keys", () => {
  const forged = token().split(".");
  forged[2] = Buffer.alloc(64).toString("base64url");
  assert.throws(() => verifyAccessToken(forged.join("."), jwks, options));
  assert.throws(() =>
    verifyAccessToken(token(), { keys: [...jwks.keys, ...jwks.keys] }, options),
  );
});
