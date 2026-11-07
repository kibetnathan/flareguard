COMPOSE ?= docker compose
ENV_FILE ?= api/.env

.PHONY: setup start up down logs migrate shell db-shell test lint clean

setup:
	@test -f $(ENV_FILE) || cp api/.env.example $(ENV_FILE)
	$(COMPOSE) up -d --build db
	@echo "Waiting for database..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		$(COMPOSE) exec -T db pg_isready -U $${POSTGRES_USER:-flareguard} -d $${POSTGRES_DB:-flareguard} >/dev/null 2>&1 && break; \
		sleep 1; \
	done
	$(COMPOSE) run --rm api uv run alembic upgrade head
	@echo "Setup complete. Run: make start"

start:
	$(COMPOSE) up --build

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=100

migrate:
	$(COMPOSE) run --rm api uv run alembic upgrade head

shell:
	$(COMPOSE) run --rm api sh

db-shell:
	$(COMPOSE) exec db psql -U $${POSTGRES_USER:-flareguard} -d $${POSTGRES_DB:-flareguard}

test:
	$(COMPOSE) run --rm api uv run --group dev pytest

lint:
	$(COMPOSE) run --rm api uv run --group dev ruff check .

clean:
	$(COMPOSE) down -v --remove-orphans
