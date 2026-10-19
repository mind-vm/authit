.DEFAULT_GOAL := help

PGTEST_DSN ?= postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable
export PGTEST_DSN

.PHONY: help generate check test ci

help: ## List the targets
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

generate: ## Regenerate pgstore's sqlc output
	sqlc generate

check: ## gofmt, vet and sqlc drift
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)
	go vet ./...
	sqlc diff

test: ## Test every package, uncached; needs Postgres at PGTEST_DSN
	go test -count=1 ./...

ci: check test ## What CI runs
