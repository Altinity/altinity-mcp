package oauth_state

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
)

// DefaultCleanupInterval is the wakeup cadence for the consumed-jti cleanup
// goroutine. Hourly is conservative — KeeperMap entries are tiny (~80 bytes)
// and our scale (~hundreds of clients refreshing ~1×/h) produces a few
// thousand new entries per day even before TTL bites. Hourly DELETEs keep
// the table bounded with no perceptible CH load. Operators can override.
const DefaultCleanupInterval = 1 * time.Hour

// DefaultCleanupRetention is how long a consumed-jti row sticks around. 35
// days = the gating-mode refresh-token TTL (30 days) plus a 5-day buffer
// for clock skew and replay-window bounds. After this point the rows are
// safe to delete: any refresh JWE that could still reference the jti has
// itself expired (its `exp` is unconditionally checked in
// decodeOAuthJWE before CheckAndConsume runs).
const DefaultCleanupRetention = 35 * 24 * time.Hour

// CleanupRunner is the subset of Store that the loop needs. Defining it
// separately lets tests inject a counter without standing up a CH harness.
type CleanupRunner interface {
	Cleanup(ctx context.Context, retention time.Duration) error
}

// StartCleanupLoop spawns a goroutine that periodically deletes consumed-
// jti rows older than `retention`. The goroutine exits when ctx is
// cancelled. Each cleanup attempt is bounded by `attemptTimeout`; failures
// are logged but never panic, so the loop is durable across CH outages.
//
// Multi-pod deployments all run their own loops — duplicate `ALTER DELETE`s
// are harmless (CH coalesces; KeeperMap deletes are idempotent on absent
// keys).
//
// Returns a "stop" function for tests; in production the caller passes a
// server-lifetime context and the returned function is rarely called.
func StartCleanupLoop(ctx context.Context, runner CleanupRunner, interval, retention, attemptTimeout time.Duration) func() {
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}
	if retention <= 0 {
		retention = DefaultCleanupRetention
	}
	if attemptTimeout <= 0 {
		attemptTimeout = 5 * time.Minute
	}

	loopCtx, cancel := context.WithCancel(ctx)

	go func() {
		log.Info().
			Dur("interval", interval).
			Dur("retention", retention).
			Msg("oauth_state cleanup loop started")
		defer log.Info().Msg("oauth_state cleanup loop stopped")

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				runOnce(loopCtx, runner, retention, attemptTimeout)
			}
		}
	}()

	return cancel
}

// runOnce executes a single cleanup attempt with a per-attempt timeout.
// Errors are logged at WARN; we never escalate to ERR because cleanup
// failure does not affect the security control (KeeperMap atomicity is
// what enforces single-claim, not the cleanup). Cleanup is just bounded-
// storage hygiene.
func runOnce(parentCtx context.Context, runner CleanupRunner, retention, attemptTimeout time.Duration) {
	attemptCtx, cancel := context.WithTimeout(parentCtx, attemptTimeout)
	defer cancel()

	if err := runner.Cleanup(attemptCtx, retention); err != nil {
		// Don't log if the parent context was cancelled — that's an
		// orderly shutdown, not a failure.
		if errors.Is(err, context.Canceled) || errors.Is(parentCtx.Err(), context.Canceled) {
			return
		}
		log.Warn().
			Err(err).
			Dur("retention", retention).
			Msg("oauth_state cleanup attempt failed (non-fatal)")
	}
}
