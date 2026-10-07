package config

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

func TestValidateJWETokenGenerator(t *testing.T) {
	for _, tt := range []struct {
		name      string
		jwe       bool
		generator bool
		admin     string
		max       int
		want      string
	}{
		{"off by default", false, false, "", -1, ""},
		{"requires JWE", false, true, strings.Repeat("a", 32), 0, "requires server.jwe.enabled"},
		{"missing admin", true, true, "", 0, "admin_token must be at least 32 bytes"},
		{"short admin", true, true, strings.Repeat("a", 31), 0, "admin_token must be at least 32 bytes"},
		{"minimum admin", true, true, strings.Repeat("a", 32), 0, ""},
		{"negative max", true, true, strings.Repeat("a", 32), -1, "max_expiry_seconds must be positive"},
		{"positive max", true, true, strings.Repeat("a", 32), 1, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := JWEConfig{Enabled: tt.jwe, TokenGenerator: JWETokenGeneratorConfig{Enabled: tt.generator, AdminToken: tt.admin, MaxExpirySeconds: tt.max}}
			err := cfg.ValidateTokenGenerator()
			if tt.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.want)
				if tt.admin != "" {
					require.NotContains(t, err.Error(), tt.admin)
				}
			}
		})
	}
	require.Equal(t, 86400, (JWETokenGeneratorConfig{}).EffectiveMaxExpirySeconds())
	require.Equal(t, 1234, (JWETokenGeneratorConfig{MaxExpirySeconds: 1234}).EffectiveMaxExpirySeconds())
}

func TestJWETokenGeneratorConfigSources(t *testing.T) {
	t.Run("YAML", func(t *testing.T) {
		var cfg Config
		require.NoError(t, yaml.Unmarshal([]byte("server:\n  jwe:\n    token_generator:\n      enabled: true\n      admin_token: fake-admin-secret-at-least-32-bytes\n      max_expiry_seconds: 1234\n"), &cfg))
		require.True(t, cfg.Server.JWE.TokenGenerator.Enabled)
		require.Equal(t, "fake-admin-secret-at-least-32-bytes", cfg.Server.JWE.TokenGenerator.AdminToken)
		require.Equal(t, 1234, cfg.Server.JWE.TokenGenerator.MaxExpirySeconds)
	})
	for _, source := range []string{"defaults", "environment", "CLI"} {
		t.Run(source, func(t *testing.T) {
			args := []string{"test"}
			if source == "environment" {
				t.Setenv("MCP_JWE_TOKEN_GENERATOR_ENABLED", "true")
				t.Setenv("MCP_JWE_TOKEN_GENERATOR_ADMIN_TOKEN", "fake-admin-secret-at-least-32-bytes")
				t.Setenv("MCP_JWE_TOKEN_GENERATOR_MAX_EXPIRY_SECONDS", "1234")
			}
			if source == "CLI" {
				args = append(args, "--jwe-token-generator", "--jwe-token-generator-admin-token", "fake-admin-secret-at-least-32-bytes", "--jwe-token-generator-max-expiry-seconds", "1234")
			}
			var cfg Config
			cmd := &cli.Command{Name: "test", Flags: BuildFlags(&cfg), Action: func(_ context.Context, cmd *cli.Command) error { ApplyFlags(&cfg, cmd); return nil }}
			require.NoError(t, cmd.Run(context.Background(), args))
			if source == "defaults" {
				require.False(t, cfg.Server.JWE.TokenGenerator.Enabled)
				require.Empty(t, cfg.Server.JWE.TokenGenerator.AdminToken)
				require.Equal(t, 86400, cfg.Server.JWE.TokenGenerator.MaxExpirySeconds)
			} else {
				require.True(t, cfg.Server.JWE.TokenGenerator.Enabled)
				require.Equal(t, "fake-admin-secret-at-least-32-bytes", cfg.Server.JWE.TokenGenerator.AdminToken)
				require.Equal(t, 1234, cfg.Server.JWE.TokenGenerator.MaxExpirySeconds)
			}
		})
	}
}
