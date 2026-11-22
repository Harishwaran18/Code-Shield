.PHONY: install dev test lint scan docker

install:
	pip install -r requirements-dev.txt

dev:
	python app.py

test:
	pytest

lint:
	ruff check server tests app.py
	bandit -r server -ll -q

scan: lint test

docker:
	docker compose up --build
