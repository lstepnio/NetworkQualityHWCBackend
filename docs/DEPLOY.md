# Deploy

This is the operator's runbook for standing up a fresh `NetworkQualityHWCBackend`
instance behind a real hostname. The lab `make dev` flow stays useful but
points at `192.168.10.233` and bakes in a kill-switched-off seed; production
needs different inputs.

## Prerequisites

- A Postgres 16 instance reachable from the runtime (managed or self-hosted).
- A way to set environment variables (Secret Manager, K8s secret, etc.).
- A DNS record + TLS for `certifier-api.gethotwired.com` (the hostname
  declared in `contract/openapi.yaml` `servers:`). Staging is
  `certifier-api.staging.gethotwired.com`.
- The published container image: `ghcr.io/lstepnio/networkqualityhwcbackend:<tag>`.
  Use the latest signed release tag (currently `0.3.0`).

## Required env vars

| Var                     | Required | Notes                                                |
|-------------------------|----------|------------------------------------------------------|
| `DATABASE_URL`          | yes      | `postgres://user:pass@host:5432/db?sslmode=require` |
| `HTTP_ADDR`             | no       | defaults to `:8080`                                  |
| `PII_PEPPER`            | yes      | 32+ random bytes; **do not change after launch** — would invalidate every existing PII hash join. Treat as a primary secret. |
| `ADMIN_TOKEN`           | yes      | shared secret for `/admin/*`. Rotate via secret store; empty disables `/admin/*` (returns 503). |
| `MIGRATIONS_PATH`       | no       | baked at `/app/db/migrations` in the image           |
| `DEV_SEED`              | **no**   | leave unset in production; the dev seed has lab values |

## First boot

The server runs `golang-migrate` migrations on startup. On a fresh DB this
creates `cert_config` and `certifications` and applies migration 0002 (drops
the FK on `certifications.config_version`). No seed runs because
`DEV_SEED` is unset.

That leaves `cert_config` empty — `GET /v1/cert-config` will return 503
until the production config is installed.

## Install the production config

Use the committed template:

```bash
ADMIN_TOKEN=$(your-secret-store-fetch ADMIN_TOKEN)
HOST=https://certifier-api.gethotwired.com

# Insert as inactive draft
curl -fsS -X POST "$HOST/admin/cert-configs" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data @db/templates/cert-config-production.json

# Promote to active (atomic swap; safe to run repeatedly)
VERSION=$(jq -r .configVersion db/templates/cert-config-production.json)
curl -fsS -X POST "$HOST/admin/cert-configs/$VERSION/activate" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

After that, `GET /v1/cert-config` returns 200 and STBs in the field will
pick up the config on next launch.

## Rolling forward

Edit the template, bump `configVersion` (the table's primary key), commit,
and run the same two-step (insert + activate) on the running stack — or
use the dashboard's `/configs/new` editor. The `Activate` step is wrapped
in a transaction with a `partial unique index` on `is_active`, so there is
always exactly one active row.

To kill-switch result publishing in an emergency, edit the active config to
set `uploadResults.enabled = false` (the dashboard editor has a one-click
toggle). STBs respect the flag and skip the POST.

## Rolling back

```bash
# List configs, find the previous active one
curl -fsS "$HOST/admin/cert-configs" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.items'

# Re-promote a previous version
curl -fsS -X POST "$HOST/admin/cert-configs/<previous-version>/activate" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Old configs are retained in the table (no cleanup) so rollback is always
just an activate call.

## Health check

`GET /healthz` returns `200 ok` once the listener is up. Use it as the
container readiness/liveness probe; it does **not** touch the DB, so a
hung Postgres doesn't take the pod down. If you want a stricter probe,
hit `GET /v1/cert-config` (which does a single SELECT) — but expect 503
until the production config is installed.
