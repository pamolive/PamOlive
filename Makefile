.PHONY: init up test

init:
	sh install.sh

up:
	docker compose up --build -d

test:
	docker compose --profile test run --rm --build test
