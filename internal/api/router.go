package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/pii"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

type Deps struct {
	Logger         *slog.Logger
	CertConfigs    *store.CertConfigStore
	Certifications *store.CertificationsStore
	PII            *pii.Hasher
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(requestID)
	r.Use(slogRequest(d.Logger))
	r.Use(recoverer(d.Logger))
	r.Use(maxBodyBytes)
	r.Use(permissiveBearer)

	cc := NewCertConfigHandler(d.CertConfigs)
	r.Get("/v1/cert-config", cc.Get)

	if d.Certifications != nil && d.PII != nil {
		certs := NewCertificationsHandler(d.Certifications, d.PII, d.Logger)
		r.Post("/v1/certifications", certs.Post)
		r.Get("/v1/certifications/{id}", certs.Get)
	}

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return r
}
