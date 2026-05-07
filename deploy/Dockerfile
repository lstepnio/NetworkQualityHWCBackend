# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS builder
WORKDIR /src

# Cache deps
COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/server /app/server
COPY db/migrations /app/db/migrations
COPY db/seed /app/db/seed

ENV MIGRATIONS_PATH=/app/db/migrations
ENV SEED_PATH=/app/db/seed/cert-config.json
ENV HTTP_ADDR=:8080

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/server"]
