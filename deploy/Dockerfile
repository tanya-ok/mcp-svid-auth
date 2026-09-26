FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --frozen --no-dev
COPY deploy/policy.yaml ./deploy/policy.yaml
ENV PATH=/app/.venv/bin:$PATH
# Runs as the UID set per service in docker-compose.yml.
USER 65534
