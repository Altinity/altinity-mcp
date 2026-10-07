package main

import (
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func TestSetupLoggingConcurrentEvents(t *testing.T) {
	// TestMain initializes formatting before any workers run, as production's
	// CLI Before hook does. Concurrent reloads must change only the atomic level.
	initialLogger := log.Logger
	initialFormat := zerolog.TimeFieldFormat
	initialLevel := zerolog.GlobalLevel()
	t.Cleanup(func() { zerolog.SetGlobalLevel(initialLevel) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				if err := setupLogging([]string{"debug", "info", "warn", "error"}[j%4]); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				log.Log().Timestamp().Int("event", j).Msg("concurrent logging setup regression")
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, initialLogger, log.Logger, "reloads must preserve the initialized logger and formatter")
	require.Equal(t, initialFormat, zerolog.TimeFieldFormat)
}
