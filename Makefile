.PHONY: dev down build test test-short tidy lint vet clean curl-config

# Local dev: docker compose up Postgres + server, with auto-migrate and seed.
dev:
	docker compose up --build

# Tear down compose and wipe volumes.
down:
	docker compose down -v

# Build the server binary into ./bin/server (requires local Go).
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/server ./cmd/server

# Full test suite (requires Docker for testcontainers-go).
test:
	go test ./... -count=1

# Skip integration tests when Docker is unavailable.
test-short:
	go test ./... -short -count=1

tidy:
	go mod tidy

vet:
	go vet ./...

lint: vet

clean:
	rm -rf bin

# Smoke check the running server (run after `make dev`).
curl-config:
	curl -is http://localhost:8080/v1/cert-config \
	  -H 'X-Device-Id: 11111111-1111-1111-1111-111111111111' \
	  -H 'X-App-Version: 0.1.0' \
	  -H 'X-Schema-Version: 1'
