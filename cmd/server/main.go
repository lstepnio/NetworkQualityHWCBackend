package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/api"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/asn"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/config"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/pii"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	env, err := config.Load()
	if err != nil {
		logger.Error("config", slog.String("err", err.Error()))
		os.Exit(1)
	}

	if err := store.RunMigrations(env.MigrationsPath, env.DatabaseURL); err != nil {
		logger.Error("migrate", slog.String("err", err.Error()))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := store.NewPool(ctx, env.DatabaseURL)
	if err != nil {
		logger.Error("db", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	cfgStore := store.NewCertConfigStore(pool)
	certStore := store.NewCertificationsStore(pool)
	appVersionStore := store.NewAppVersionStore(pool)
	hasher := pii.NewHasher(env.PIIPepper)

	var asnLookup asn.Lookup = asn.Noop{}
	if env.ASNLookupEnabled {
		asnLookup = asn.NewCymru(env.ASNLookupTimeout)
	}

	if env.DevSeed {
		if err := store.SeedIfEmpty(ctx, cfgStore, env.SeedPath, logger); err != nil {
			logger.Error("seed", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}

	router := api.NewRouter(api.Deps{
		Logger:         logger,
		CertConfigs:    cfgStore,
		Certifications: certStore,
		AppVersions:    appVersionStore,
		PII:            hasher,
		ASN:            asnLookup,
		AdminToken:     env.AdminToken,
	})

	srv := &http.Server{
		Addr:              env.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("listening", slog.String("addr", env.HTTPAddr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown", slog.String("err", err.Error()))
	}
}
