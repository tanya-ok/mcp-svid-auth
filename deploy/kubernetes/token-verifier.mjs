import { createPublicKey, verify } from "node:crypto";

export async function fetchIssuerKeys(issuer, fetcher = fetch) {
  const response = await fetcher(`${issuer}/jwks.json`, {
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error("invalid_token");
  const raw = await response.text();
  if (raw.length > 65536) throw new Error("invalid_token");
  return JSON.parse(raw);
}

export function requireToolScopes(names, scopes) {
  if (
    names.length === 0 ||
    new Set(names).size !== names.length ||
    Object.keys(scopes).length !== names.length ||
    names.some((name) => scopes[name] !== "fhir:read")
  ) {
    throw new Error("scope_configuration_invalid");
  }
}

// All diagnostics are fixed strings. No unverified claim enters output.
export function verifyAccessToken(
  token,
  jwks,
  { issuer, resource, caller, now = Date.now() / 1000 },
) {
  if (typeof token !== "string" || token.length > 16384)
    throw new Error("invalid_token");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p)))
    throw new Error("invalid_token");
  try {
    const header = JSON.parse(
      Buffer.from(parts[0], "base64url").toString("utf8"),
    );
    const claims = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    if (
      header.typ !== "at+jwt" ||
      header.alg !== "ES256" ||
      typeof header.kid !== "string" ||
      header.crit !== undefined ||
      header.jku !== undefined ||
      header.jwk !== undefined
    )
      throw new Error();
    const matching = jwks.keys.filter(
      (k) =>
        k.kid === header.kid &&
        k.kty === "EC" &&
        k.crv === "P-256" &&
        (k.alg === undefined || k.alg === "ES256") &&
        (k.use === undefined || k.use === "sig"),
    );
    if (matching.length !== 1) throw new Error();
    const signature = Buffer.from(parts[2], "base64url");
    if (
      signature.length !== 64 ||
      !verify(
        "sha256",
        Buffer.from(`${parts[0]}.${parts[1]}`),
        {
          key: createPublicKey({ key: matching[0], format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        },
        signature,
      )
    )
      throw new Error();
    if (
      claims.iss !== issuer ||
      claims.aud !== resource ||
      claims.sub !== caller ||
      !Number.isFinite(claims.exp) ||
      !Number.isFinite(claims.iat) ||
      claims.exp <= now ||
      claims.iat > now ||
      claims.exp <= claims.iat ||
      claims.exp - claims.iat > 300 ||
      (claims.nbf !== undefined &&
        (!Number.isFinite(claims.nbf) || claims.nbf > now))
    )
      throw new Error();
    if (
      typeof claims.scope !== "string" ||
      !claims.scope.split(" ").includes("fhir:read")
    )
      throw new Error("insufficient_scope");
    return claims;
  } catch (err) {
    throw new Error(
      err?.message === "insufficient_scope"
        ? "insufficient_scope"
        : "invalid_token",
    );
  }
}
