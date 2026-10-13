FROM docker.io/library/python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
COPY --from=ghcr.io/astral-sh/uv:0.11.19@sha256:b46b03ddfcfbf8f547af7e9eaefdf8a39c8cebcba7c98858d3162bd28cf536f6 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY mcp-svid-auth/pyproject.toml mcp-svid-auth/uv.lock mcp-svid-auth/README.md mcp-svid-auth/LICENSE mcp-svid-auth/NOTICE ./
COPY mcp-svid-auth/src ./src
RUN uv sync --frozen --no-dev
COPY mcp-svid-auth/deploy/kubernetes/policy.yaml ./deploy/policy.yaml
COPY mcp-svid-auth/deploy/probe_svid.py ./deploy/probe_svid.py
COPY mcp-svid-auth/deploy/probe_mtls.py ./deploy/probe_mtls.py
COPY hipaa-fhir-mcp/deploy/kubernetes/probe_fhir.py ./deploy/probe_fhir.py
ENV PATH=/app/.venv/bin:$PATH
USER 65534
