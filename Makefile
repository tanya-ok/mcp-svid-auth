.PHONY: check test lint docs-check demo down

check: lint docs-check test

test:
	uv run pytest -q

lint:
	uv run ruff check
	uv run ruff format --check .
	uv run mypy

docs-check:
	uv run python scripts/gen_config_docs.py --check

demo:
	./deploy/demo.sh

down:
	docker compose -f deploy/docker-compose.yml down -v
