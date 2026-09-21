.PHONY: install install-dev lint typecheck security-scan dependency-audit test test-security ci run keys token docker-build docker-up docker-down

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

lint:
	ruff check .

typecheck:
	mypy app

security-scan:
	bandit -r app -q

dependency-audit:
	pip-audit -r requirements.txt

test:
	pytest -v

test-security:
	pytest -v tests/security

ci: lint typecheck test security-scan dependency-audit

keys:
	python -m scripts.issue_token --generate-keys-only

run:
	uvicorn app.main:app --reload --port 8000

token:
	python -m scripts.issue_token --user $(USER_ID)

docker-build:
	docker build -t authorization-gateway .

docker-up:
	docker compose up --build

docker-down:
	docker compose down
