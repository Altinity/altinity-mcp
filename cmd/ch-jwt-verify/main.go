// Command ch-jwt-verify is a single-binary HTTP server that ClickHouse calls
// from its <http_authentication> handler to validate JWT bearers. The MCP
// gateway no longer impersonates users to ClickHouse via cluster_secret;
// instead, each ClickHouse query goes through this sidecar so the cryptographic
// gate sits next to the data plane.
//
// Wire contract: ClickHouse POSTs Authorization: Basic base64(email:JWT). The
// sidecar verifies the JWT (signature + iss + aud + exp + scope) and answers
// 200 with optional session settings, or any non-200 to reject the query.
package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

var version = "dev"

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	app := &cli.Command{
		Name:    "ch-jwt-verify",
		Usage:   "JWT verifier sidecar for ClickHouse http_authentication",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to YAML config file",
				Value:   "/etc/ch-jwt-verify/config.yaml",
				Sources: cli.EnvVars("CH_JWT_VERIFY_CONFIG"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "Logging level (debug/info/warn/error)",
				Value:   "info",
				Sources: cli.EnvVars("CH_JWT_VERIFY_LOG_LEVEL"),
			},
		},
		Action: run,
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Msg("ch-jwt-verify exited with error")
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	if lvl, err := zerolog.ParseLevel(cmd.String("log-level")); err == nil {
		zerolog.SetGlobalLevel(lvl)
	}

	cfg, err := LoadConfig(cmd.String("config"))
	if err != nil {
		return err
	}

	verifier := NewVerifier(cfg)

	signalCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// Background reaper prunes expired cache entries on a fixed cadence.
	// Insertion-time eviction in storeCache is the primary memory bound;
	// the reaper is housekeeping for the common case where token churn is
	// low enough that entries naturally TTL out before any cap eviction.
	verifier.StartReaper(signalCtx, 5*time.Minute)

	mux := http.NewServeMux()
	mux.Handle("/verify", verifier.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	listener, network, address, err := buildListener(cfg.Listen)
	if err != nil {
		return err
	}
	log.Info().Str("network", network).Str("address", address).Str("version", version).Msg("ch-jwt-verify listening")

	errCh := make(chan error, 1)
	go func() {
		if serveErr := srv.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case <-signalCtx.Done():
		log.Info().Msg("ch-jwt-verify shutting down")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// buildListener picks Unix (preferred) or TCP. For Unix, we remove any stale
// socket left from a crashed previous run — `os.Remove` errors are tolerated
// if the path doesn't exist.
func buildListener(cfg ListenConfig) (net.Listener, string, string, error) {
	if cfg.Unix != "" {
		_ = os.Remove(cfg.Unix)
		l, err := net.Listen("unix", cfg.Unix)
		if err != nil {
			return nil, "", "", err
		}
		// Permissions 0660 keeps the socket reachable only by uid/gid the pod
		// runs as — ClickHouse and the sidecar share the same securityContext
		// in the StatefulSet pod, so they share the group.
		if err := os.Chmod(cfg.Unix, 0o660); err != nil {
			_ = l.Close()
			return nil, "", "", err
		}
		return l, "unix", cfg.Unix, nil
	}
	l, err := net.Listen("tcp", cfg.TCP)
	if err != nil {
		return nil, "", "", err
	}
	return l, "tcp", cfg.TCP, nil
}
