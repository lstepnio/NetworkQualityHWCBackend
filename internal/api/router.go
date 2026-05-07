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
	AdminToken     string
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(requestID)
	r.Use(slogRequest(d.Logger))
	r.Use(recoverer(d.Logger))

	// Device-facing /v1/* routes get the 256 KB body cap and the permissive
	// bearer middleware. /admin/* routes get a stricter shared-secret check
	// so the surfaces are isolated.
	r.Group(func(r chi.Router) {
		r.Use(maxBodyBytes)
		r.Use(permissiveBearer)

		cc := NewCertConfigHandler(d.CertConfigs)
		r.Get("/v1/cert-config", cc.Get)

		if d.Certifications != nil && d.PII != nil {
			certs := NewCertificationsHandler(d.Certifications, d.PII, d.Logger)
			r.Post("/v1/certifications", certs.Post)
			r.Get("/v1/certifications/{id}", certs.Get)
		}
	})

	if d.Certifications != nil && d.CertConfigs != nil {
		admin := NewAdminHandler(d.Certifications, d.CertConfigs)
		r.Group(func(r chi.Router) {
			r.Use(adminBearer(d.AdminToken))
			r.Get("/admin/certifications", admin.ListCertifications)
			r.Get("/admin/certifications/{id}", admin.GetCertification)
			r.Get("/admin/cert-configs", admin.ListCertConfigs)
			r.Get("/admin/cert-configs/{version}", admin.GetCertConfig)
		})
	}

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return r
}
