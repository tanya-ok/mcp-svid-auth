# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). No version has been
published as a package.

## [Unreleased]

### Added

- In-process tool response poisoning scenario (`make attack-scenarios`) with a design check for RFC 8693 style delegated scope narrowing.
- Hash-chained audit lines, terminal checkpoints and the `mcp-svid-audit-verify` command.
- Grant policy reload on SIGHUP or file change; tool calls bounded by the caller token expiry.
- Scripted threat model demo scenarios, later run as eighteen asserted scenarios in a shared Kubernetes lab on Lima, k3s and containerd with SPIRE.
- Read-only Headlamp interface and an optional passwordless ZITADEL viewer for the lab.
- Request and verification budgets, and planned signing key rotation with public key overlap.
- Local MCP review orchestration (quorum) with recorded portfolio review evidence.
- Independent TypeScript MCP SDK interoperability check, package validation and GitHub Pages documentation workflow.
- Python 3.12 and 3.13 CI matrix, Node setup from `.nvmrc`, job timeouts and grouped Dependabot updates.
- Changelog, contributing guide, code owners, issue and pull request templates, `.editorconfig` and package metadata URLs, classifiers and keywords.

### Changed

- Discovery URLs require https and public addresses unless development flags allow otherwise.
- The stdio wrapper stops the child when an exported environment token expires.
- The Podman runtime path was retired; containerd is the only lab runtime.
- The quickstart leads with the single-repository offline path; the full lab is labelled as requiring unpublished components.
- Retired signing keys expire on the injected clock instead of wall-clock time.

### Security

- Raised PyJWT to 2.15 (spiffe to 0.3.2) for published advisories.
- A JWKS with malformed keys now denies the token with audit reason `jwks_invalid` instead of an unhandled error.
- Bumped the TypeScript MCP SDK used by the interop example to 1.32.1 (GHSA-6qxp-vccf-f47h).
- Public task exports no longer include actor identities.
- Added a path-scoped gitleaks fingerprint for the verified review packet hash.

## [0.1.0] - 2026-09-27

### Added

- Token endpoint that exchanges a JWT-SVID client assertion for a short-lived, audience-bound ES256 access token.
- Notes MCP server over Streamable HTTP with per-tool scopes, deny by default and audit lines.
- Agent client with a token replay demo mode, and a stdio wrapper that hands the child a refreshed token file.
- JWT-SVID replay rejection by `jti`, a trusted issuer allowlist and scope-filtered tool listing.
- SPIRE compose demo, offline tests, STPA-Sec threat model, generated configuration reference and documentation site.
