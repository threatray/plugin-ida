PROJECT:=threatray-ida

# Declare all targets as phony targets
# https://www.gnu.org/software/make/manual/make.html#Phony-Targets
.PHONY: %

# By default, `make` without arguments runs the first target in the Makefile.
# Hence let's declare it explicitly.
_default:


unit-tests: unit-tests-latest unit-tests-3-10

unit-tests-%:
	docker compose -f docker-compose.yml --profile $@ build
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans
	docker compose -f docker-compose.yml --profile $@ up --exit-code-from $(PROJECT)-$@
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans


int-tests: int-tests-latest int-tests-3-10

int-tests-%:
	docker compose -f docker-compose.yml --profile $@ build --pull
	docker compose -f docker-compose.yml --profile $@ down
	docker compose -f docker-compose.yml --profile $@ up --exit-code-from $(PROJECT)-$@
	docker compose -f docker-compose.yml --profile $@ down --remove-orphans

test: unit-tests int-tests

lint:
	docker compose -f docker-compose.yml --profile lint build --pull
	docker compose -f docker-compose.yml --profile lint down --remove-orphans
	docker compose -f docker-compose.yml --profile lint run vulture
	docker compose -f docker-compose.yml --profile lint down --remove-orphans
	docker compose -f docker-compose.yml --profile lint run ruff-latest
	docker compose -f docker-compose.yml --profile lint down --remove-orphans
	docker compose -f docker-compose.yml --profile lint run ruff-external
	docker compose -f docker-compose.yml --profile lint down --remove-orphans

lint-fix:
	docker compose -f docker-compose.yml --profile lint-fix build --pull
	docker compose -f docker-compose.yml --profile lint-fix down
	docker compose -f docker-compose.yml --profile lint-fix run ruff-fix
	docker compose -f docker-compose.yml --profile lint-fix down --remove-orphans

lock:
	docker build --target lock -t $(PROJECT) --pull .
	docker run $(PROJECT) bash -c "cat uv.lock" > uv.lock

type-check: type-check-latest

type-check-%:
	docker compose -f docker-compose.yml build $@
	docker compose -f docker-compose.yml run $@
	docker compose -f docker-compose.yml down --remove-orphans
