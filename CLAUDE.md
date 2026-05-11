# CLAUDE.md — NetworkQualityHWCBackend

## Role

Go server for the FisionTV+ Network Certifier. Serves:

- **`/v1/*`** — device-facing endpoints consumed by the Android STB client:
  - `GET /v1/cert-config` — runtime configuration (thresholds, probe targets), with `ETag` + `If-None-Match`.
  - `POST /v1/certifications` — certification result ingest, idempotent via `payload_hash` SHA-256.
  - `GET /v1/certifications/{id}` — single result lookup.
  - `GET /v1/app/version` — app-update manifest (versionCode, APK URL, sha256, signing-cert sha256). Returns **404** when no manifest is active (not 503).
- **`/admin/*`** — admin-facing CRUD for the dashboard. Bearer-token guarded (env `ADMIN_TOKEN`).

Postgres-backed. `chi` router, `pgx/v5`, `golang-migrate`, `kin-openapi` for runtime request validation against the contract.

## Neighbors

This repo is one of four in the FisionTV+ system. All checked out under `/Users/lukasz.stepniowski/Development/`:

- **contract** — `fisiontv-cert-contract` — OpenAPI 3.1 + SPEC.md. Vendored here as the `contract/` git submodule, **pinned to an exact tag** (currently `v1.2.0`). Backend + android pins must match.
- **android** — `NetworkQualityHWC` — Kotlin/Compose STB client. Hits `/v1/*` for cert flow and self-updates via `/v1/app/version`.
- **dashboard** — `NetworkQualityHWCDashboard` — SvelteKit 5 admin UI. Hits `/admin/*` for config + manifest management.

## Local dev

```
make dev          # docker compose up: postgres + migrations + server
make migrate-up   # apply migrations
make test         # go test ./...
make build        # static binary
```

Backend listens on `:8080` (host); Docker port-maps `:18080` for the STB to reach via `http://192.168.10.233:18080`.
Postgres: `docker compose exec -T postgres psql -U certifier certifier -c "..."`.

Admin token in dev: `dev-admin-token-change-me` (see `docker-compose.yml`). Always send as `Authorization: Bearer dev-admin-token-change-me`.

## Conventions

- **PR-only.** Sandbox blocks direct push to `main`. Workflow: `git checkout -b <type>/<name>` → commit → push → `gh pr create` → wait for CI green → `gh pr merge --merge --delete-branch` → fast-forward main → tag if releasing.
- **Conventional Commits.** `feat:`, `fix:`, `ci:`, `chore:`, `docs:`, `refactor:`, `test:`.
- **Contract pin discipline.** `git -C contract describe --tags --exact-match` must return a clean tag (no `-N-gSHA` suffix). CI enforces this in `build.yml`.
- **Don't drop / mutate the `certifications` table in dev.** Run history is the only way to validate the STB pipeline end-to-end.
- **PII hashing on ingest.** SHA-256 + server pepper for `bssid`, `ssid`, `publicIp`, `gatewayIp`, `ethernetMac`, `wifiMac`. Raw values never persisted. HSN is **not** hashed (it's the join key to HWC account management).

## Release flow

1. Open a PR with the change.
2. CI green → merge.
3. Fast-forward `main` locally.
4. `git tag -a vX.Y.Z -m "vX.Y.Z: <one-line>" HEAD && git push origin vX.Y.Z`.
5. The release workflow builds and pushes a multi-arch image to GHCR.

Tag-only releases (no code change) are valid when aligning a release train with another repo's bump — see the parent project memory.

## Operational notes

- The contract submodule is read-only at runtime — `internal/openapi/validator.go` loads `contract/openapi.yaml` at boot.
- The dev seed (`db/seed/cert-config.json`) lands an `uploadResults.enabled = true` config; flipping that to `false` will silently block STB POSTs.
- `payload_hash` is the dedupe key for `POST /v1/certifications`. Same bytes → 200 (idempotent). Different bytes for the same `certification_id` → 409 conflict.
