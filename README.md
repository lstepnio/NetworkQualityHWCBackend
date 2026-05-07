# NetworkQualityHWCBackend

Backend for the **FisionTV+ Network Certifier** Android client
([NetworkQualityHWC](https://github.com/lstepnio/NetworkQualityHWC)).

The OpenAPI contract lives in
[fisiontv-cert-contract](https://github.com/lstepnio/fisiontv-cert-contract)
and is consumed here as the `contract/` git submodule, pinned to `v1.0.0`.

## Endpoints

| Method | Path                              | Status     |
|--------|-----------------------------------|------------|
| GET    | `/v1/cert-config`                 | shipped    |
| POST   | `/v1/certifications`              | shipped    |
| GET    | `/v1/certifications/{id}`         | shipped    |
| GET    | `/healthz`                        | shipped    |

`POST /v1/certifications` is idempotent on `certificationId`: the same id
with the same body returns 200 and a single stored row; the same id with a
different body returns 409 (`payload_hash` mismatch). The response body is
the canonical, PII-redacted form of the stored payload.

`GET /v1/certifications/{id}` returns the stored (PII-redacted) payload, or
404 if the id is unknown.

## Decisions

- **Stack.** Go 1.25, `chi`, `pgx/v5`, `golang-migrate`, stdlib `log/slog`.
  Single static binary; runs anywhere.
- **Auth.** Permissive bearer for v1: any non-empty `Authorization: Bearer …`
  is accepted; no header is also accepted (matches the client's current
  `NoAuthProvider`). Identity comes from the required `X-Device-Id` header.
  Tighten by swapping `internal/api/middleware.go:permissiveBearer`.
- **Hostname.** `certifier-api.gethotwired.com` (prod) /
  `certifier-api.staging.gethotwired.com` (staging) — declared in the
  contract's `openapi.yaml` `servers:` block.
- **Deploy target.** Portable. The container takes config from env vars,
  logs JSON to stdout, ships migrations + seed inside the image. Pick the
  runtime when ready.
- **PII.** `bssid` / `ssid` / `publicIp` / `gatewayIp` / `ethernetMac` /
  `wifiMac` / `hsn` are redacted on ingest with peppered SHA-256
  (`PII_PEPPER` env var). Raw values never reach disk; the rewrite happens
  in `internal/pii/hash.go` before the JSONB payload is persisted. Hashing
  is deterministic so the same identifier remains joinable across rows.

## Run locally

```bash
git clone --recursive <this repo>
cd NetworkQualityHWCBackend
make dev          # docker compose: Postgres + server with auto-migrate + seed
make curl-config  # smoke-test GET /v1/cert-config
```

The server seeds the active config from `db/seed/cert-config.json` (a copy of
`contract/fixtures/cert-config.example.json`) on first boot when `DEV_SEED=1`.
On subsequent boots the seed is skipped.

## Tests

```bash
make test         # spins up Postgres via testcontainers; requires Docker
```

## Layout

```
cmd/server/             entrypoint
internal/api/           chi router, middleware, handlers
internal/store/         pgx pool, queries, migrations, seed loader
internal/config/        env-var loader
db/migrations/          golang-migrate .sql files
db/seed/                dev/staging seed JSON
contract/               git submodule → fisiontv-cert-contract @ v1.0.0
deploy/Dockerfile       multi-stage build, distroless runtime
docker-compose.yml      local Postgres + server
.github/workflows/      CI: build + test on PR; tag-driven container release to GHCR
```

## Configuration (env vars)

| Var                | Required | Default                       | Notes                               |
|--------------------|----------|-------------------------------|-------------------------------------|
| `DATABASE_URL`     | yes      | —                             | Postgres DSN                        |
| `HTTP_ADDR`        | no       | `:8080`                       |                                     |
| `MIGRATIONS_PATH`  | no       | `db/migrations`               | overridden in the Docker image      |
| `SEED_PATH`        | no       | `db/seed/cert-config.json`    | overridden in the Docker image      |
| `DEV_SEED`         | no       | unset                         | `1` to seed an empty DB at startup  |
| `PII_PEPPER`       | no       | `dev-pepper-change-me`        | required-ish in prod                |

## Contract bumps

Schema additions only — never removals — until every fielded client supports
the new shape. To add a field:

1. Edit `openapi.yaml` in the contract repo.
2. Bump `CHANGELOG.md` per its semver rules (additive = minor).
3. Tag the contract repo (e.g. `v1.1.0`).
4. Bump the submodule pin in this repo and in `NetworkQualityHWC` together.
