.PHONY: check test lint demo down

check: lint test

test:
	uv run pytest -q

lint:
	uv run ruff check
	uv run ruff format --check .
	uv run mypy

demo:
	./deploy/demo.sh

down:
	docker compose -f deploy/docker-compose.yml down -v
