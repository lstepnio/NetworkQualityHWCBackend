package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/pii"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

type Deps struct {
	Logger         *slog.Logger
	DB             *pgxpool.Pool // for /healthz; may be nil in tests that don't need DB-backed health
	CertConfigs    *store.CertConfigStore
	Certifications *store.CertificationsStore
	AppVersions    *store.AppVersionStore
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

		if d.AppVersions != nil {
			av := NewAppVersionHandler(d.AppVersions)
			r.Get("/v1/app/version", av.Get)
		}
	})

	if d.Certifications != nil && d.CertConfigs != nil && d.AppVersions != nil && d.PII != nil {
		admin := NewAdminHandler(d.Certifications, d.CertConfigs, d.AppVersions, d.PII)
		r.Group(func(r chi.Router) {
			r.Use(adminBearer(d.AdminToken))
			r.Use(maxBodyBytes)
			r.Get("/admin/certifications", admin.ListCertifications)
			r.Get("/admin/certifications/{id}", admin.GetCertification)
			r.Get("/admin/cert-configs", admin.ListCertConfigs)
			r.Get("/admin/cert-configs/{version}", admin.GetCertConfig)
			r.Post("/admin/cert-configs", admin.CreateCertConfig)
			r.Post("/admin/cert-configs/{version}/activate", admin.ActivateCertConfig)
			r.Get("/admin/app-versions", admin.ListAppVersions)
			r.Get("/admin/app-versions/{versionCode}", admin.GetAppVersion)
			r.Post("/admin/app-versions", admin.CreateAppVersion)
			r.Post("/admin/app-versions/{versionCode}/activate", admin.ActivateAppVersion)
			r.Get("/admin/queue-stats", admin.QueueStats)
		})
	}

	// /healthz pings the DB so orchestrators / load balancers can route
	// away from instances that are alive-but-broken. 500ms budget keeps
	// the probe cheap; on miss we return 503 with a structured body so
	// the alert text in logs is actionable.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if d.DB == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		if err := d.DB.Ping(ctx); err != nil {
			d.Logger.Warn("healthz: db ping failed", slog.String("err", err.Error()))
			writeError(w, http.StatusServiceUnavailable, "db unreachable")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return r
}
