.PHONY: interop package check test lint docs-check up demo down runtime-up runtime-stop lab-render ui ui-stop ui-login ui-login-down identity-demo google-config-init google-config-check google-setup-demo

check: lint docs-check test

test:
	uv run pytest -q

lint:
	uv run ruff check
	uv run ruff format --check .
	uv run mypy

docs-check:
	uv run python scripts/gen_config_docs.py --check

up: runtime-up
	uv run --locked python -m scripts.kubernetes_demo up

demo: up
	uv run --locked python -m scripts.run_demo

down:
	uv run --locked python -m scripts.kubernetes_demo down

runtime-up:
	uv run --locked python -m scripts.kubernetes_demo runtime-up

runtime-stop:
	uv run --locked python -m scripts.kubernetes_demo runtime-stop

lab-render:
	uv run --locked python -m scripts.kubernetes_demo render

ui:
	uv run --locked python -m scripts.kubernetes_ui start

ui-stop:
	uv run --locked python -m scripts.kubernetes_ui stop

ui-login:
	uv run --locked python -m scripts.zitadel_demo up
	uv run --locked python -m scripts.kubernetes_ui start

ui-login-down:
	uv run --locked python -m scripts.zitadel_demo down

identity-demo:
	uv run --locked python -m scripts.run_identity_demo

google-config-init:
	uv run --locked python -m scripts.google_identity_config init

google-config-check:
	uv run --locked python -m scripts.google_identity_config check

google-setup-demo:
	uv run --locked python -m scripts.run_google_setup_demo

interop:
	uv run --locked python scripts/check_interop.py

package:
	uv build
	uv run --locked python scripts/check_dist.py

.PHONY: quorum-demo quorum-prepare
quorum-demo:
	uv run --locked python -m scripts.quorum demo

quorum-prepare:
	uv run --locked python -m scripts.quorum prepare
