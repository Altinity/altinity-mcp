package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// TestBuildConfigFromClaims tests building ClickHouse config from JWE claims
func TestBuildConfigFromClaims(t *testing.T) {
	t.Parallel()
	chConfig := config.ClickHouseConfig{
		Host:     "default-host",
		Port:     8123,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
		Limit:    1000,
	}

	jweConfig := config.JWEConfig{
		Enabled:      true,
		JWESecretKey: "test-secret",
	}

	srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

	t.Run("basic_claims", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     "jwe-host",
			"port":     float64(9000),
			"database": "jwe-db",
			"username": "jwe-user",
			"password": "jwe-pass",
			"protocol": "tcp",
			"limit":    float64(500),
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.Equal(t, "jwe-host", cfg.Host)
		require.Equal(t, 9000, cfg.Port)
		require.Equal(t, "jwe-db", cfg.Database)
		require.Equal(t, "jwe-user", cfg.Username)
		require.Equal(t, "jwe-pass", cfg.Password)
		require.Equal(t, "tcp", string(cfg.Protocol))
		require.Equal(t, 500, cfg.Limit)
	})

	t.Run("tls_claims", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": true,
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.True(t, cfg.TLS.Enabled)
		require.Equal(t, "/path/to/ca.crt", cfg.TLS.CaCert)
		require.Equal(t, "/path/to/client.crt", cfg.TLS.ClientCert)
		require.Equal(t, "/path/to/client.key", cfg.TLS.ClientKey)
		require.True(t, cfg.TLS.InsecureSkipVerify)
	})

	t.Run("empty_claims", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
		require.Equal(t, "default", cfg.Database)
	})

	t.Run("invalid_types", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host": 123,       // Should be string
			"port": "invalid", // Should be number
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values for invalid types
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
	})
}

// fakeJWT assembles a syntactically-valid 3-segment JWT with the supplied
// payload object. The header and signature are fixed placeholders — the
// emailFromUnverifiedJWT helper doesn't look at either.
func fakeJWT(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString(body)
	return head + "." + pay + ".sig"
}

func TestEmailFromUnverifiedJWT(t *testing.T) {
	t.Parallel()

	t.Run("standard_email_claim", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"email": "alice@example.com"})
		got, ok := emailFromUnverifiedJWT(tok)
		require.True(t, ok)
		require.Equal(t, "alice@example.com", got)
	})

	t.Run("namespaced_email_fallback", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{
			"https://example.com/email": "alice@example.com",
		})
		got, ok := emailFromUnverifiedJWT(tok)
		require.True(t, ok)
		require.Equal(t, "alice@example.com", got)
	})

	t.Run("standard_email_takes_precedence_over_namespaced", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{
			"email":                     "primary@example.com",
			"https://example.com/email": "secondary@example.com",
		})
		got, ok := emailFromUnverifiedJWT(tok)
		require.True(t, ok)
		require.Equal(t, "primary@example.com", got)
	})

	t.Run("empty_string_email_falls_back", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{
			"email":                     "  ",
			"https://example.com/email": "fallback@example.com",
		})
		got, ok := emailFromUnverifiedJWT(tok)
		require.True(t, ok)
		require.Equal(t, "fallback@example.com", got)
	})

	t.Run("no_email_claim_at_all", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"sub": "u-1"})
		_, ok := emailFromUnverifiedJWT(tok)
		require.False(t, ok)
	})

	t.Run("non_string_email_claim", func(t *testing.T) {
		t.Parallel()
		// JWT carrying email as a number is malformed but shouldn't crash.
		tok := fakeJWT(t, map[string]interface{}{"email": 12345})
		_, ok := emailFromUnverifiedJWT(tok)
		require.False(t, ok)
	})

	t.Run("not_a_jwt_two_segments", func(t *testing.T) {
		t.Parallel()
		_, ok := emailFromUnverifiedJWT("only.two")
		require.False(t, ok)
	})

	t.Run("jwe_five_segments_rejected", func(t *testing.T) {
		t.Parallel()
		// A JWE (encrypted JWT) has 5 segments. Our path is JWT-only.
		_, ok := emailFromUnverifiedJWT("a.b.c.d.e")
		require.False(t, ok)
	})

	t.Run("empty_token", func(t *testing.T) {
		t.Parallel()
		_, ok := emailFromUnverifiedJWT("")
		require.False(t, ok)
	})

	t.Run("malformed_base64_payload", func(t *testing.T) {
		t.Parallel()
		_, ok := emailFromUnverifiedJWT("header.!!not-base64!!.sig")
		require.False(t, ok)
	})

	t.Run("malformed_json_payload", func(t *testing.T) {
		t.Parallel()
		bogus := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
		_, ok := emailFromUnverifiedJWT("head." + bogus + ".sig")
		require.False(t, ok)
	})

	t.Run("padded_base64_url_fallback", func(t *testing.T) {
		t.Parallel()
		// Some IdPs emit padded segments; our decoder tries RawURL then URL.
		body, _ := json.Marshal(map[string]interface{}{"email": "alice@example.com"})
		padded := base64.URLEncoding.EncodeToString(body) // includes '=' padding
		tok := "head." + padded + ".sig"
		got, ok := emailFromUnverifiedJWT(tok)
		require.True(t, ok)
		require.Equal(t, "alice@example.com", got)
	})

	t.Run("leading_trailing_whitespace_trimmed", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"email": "  alice@example.com  "})
		got, ok := emailFromUnverifiedJWT(tok)
		require.True(t, ok)
		require.Equal(t, "alice@example.com", got)
	})
}

// TestBasicUsernameFromJWT covers the orchestration around the configurable
// username_claim: unset preserves the email default (incl. namespaced
// fallback); a set claim does a strict top-level lookup and fails closed on
// missing/empty/non-string, never falling back to email.
func TestBasicUsernameFromJWT(t *testing.T) {
	t.Parallel()

	t.Run("unset_claim_uses_email", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"email": "alice@example.com"})
		got, ok := basicUsernameFromJWT(tok, "")
		require.True(t, ok)
		require.Equal(t, "alice@example.com", got)
	})

	t.Run("unset_claim_whitespace_uses_email", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"email": "alice@example.com"})
		got, ok := basicUsernameFromJWT(tok, "   ")
		require.True(t, ok)
		require.Equal(t, "alice@example.com", got)
	})

	t.Run("unset_claim_namespaced_email_fallback", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{
			"https://example.com/email": "alice@example.com",
		})
		got, ok := basicUsernameFromJWT(tok, "")
		require.True(t, ok)
		require.Equal(t, "alice@example.com", got)
	})

	t.Run("configured_username_claim", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{
			"username": "alice",
			"email":    "alice@example.com",
		})
		got, ok := basicUsernameFromJWT(tok, "username")
		require.True(t, ok)
		require.Equal(t, "alice", got)
	})

	t.Run("configured_claim_whitespace_trimmed", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"preferred_username": "  bob  "})
		got, ok := basicUsernameFromJWT(tok, "preferred_username")
		require.True(t, ok)
		require.Equal(t, "bob", got)
	})

	t.Run("configured_claim_missing_fails_closed", func(t *testing.T) {
		t.Parallel()
		// email present but the configured claim is absent — must NOT fall back.
		tok := fakeJWT(t, map[string]interface{}{"email": "alice@example.com"})
		_, ok := basicUsernameFromJWT(tok, "username")
		require.False(t, ok)
	})

	t.Run("configured_claim_empty_fails_closed", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"username": "   "})
		_, ok := basicUsernameFromJWT(tok, "username")
		require.False(t, ok)
	})

	t.Run("configured_claim_non_string_fails_closed", func(t *testing.T) {
		t.Parallel()
		tok := fakeJWT(t, map[string]interface{}{"username": 12345})
		_, ok := basicUsernameFromJWT(tok, "username")
		require.False(t, ok)
	})

	t.Run("configured_email_is_strict_top_level", func(t *testing.T) {
		t.Parallel()
		// With username_claim="email" set, the namespaced */email key is NOT
		// consulted — explicit config means a strict single-claim lookup.
		tok := fakeJWT(t, map[string]interface{}{
			"https://example.com/email": "namespaced@example.com",
		})
		_, ok := basicUsernameFromJWT(tok, "email")
		require.False(t, ok)
	})

	t.Run("configured_claim_not_a_jwt_fails_closed", func(t *testing.T) {
		t.Parallel()
		_, ok := basicUsernameFromJWT("only.two", "username")
		require.False(t, ok)
	})
}

// jwtWithClaims builds an unsigned-but-well-formed three-segment JWT string
// (the signature segment is a dummy) for exp-claim tests. unverifiedExp never
// checks the signature, so this is sufficient.
func jwtWithClaims(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	return "header." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

func TestUnverifiedExpAndOAuthTokenExpired(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{Config: config.Config{
		Server: config.ServerConfig{OAuth: config.OAuthConfig{Enabled: true}},
	}}

	t.Run("expired_jwt", func(t *testing.T) {
		t.Parallel()
		exp := time.Now().Add(-time.Hour).Unix()
		tok := jwtWithClaims(t, map[string]interface{}{"exp": exp})
		gotExp, isJWT := unverifiedExp(tok)
		require.True(t, isJWT)
		require.Equal(t, exp, gotExp)
		require.True(t, srv.OAuthTokenExpired(tok))
	})

	t.Run("unexpired_jwt", func(t *testing.T) {
		t.Parallel()
		tok := jwtWithClaims(t, map[string]interface{}{"exp": time.Now().Add(time.Hour).Unix()})
		_, isJWT := unverifiedExp(tok)
		require.True(t, isJWT)
		require.False(t, srv.OAuthTokenExpired(tok))
	})

	t.Run("within_clock_skew_not_expired", func(t *testing.T) {
		t.Parallel()
		// Expired 30s ago — inside the 60s skew window, so NOT treated as expired.
		tok := jwtWithClaims(t, map[string]interface{}{"exp": time.Now().Add(-30 * time.Second).Unix()})
		require.False(t, srv.OAuthTokenExpired(tok))
	})

	t.Run("opaque_token_softpasses", func(t *testing.T) {
		t.Parallel()
		_, isJWT := unverifiedExp("opaque-access-token")
		require.False(t, isJWT)
		require.False(t, srv.OAuthTokenExpired("opaque-access-token"))
	})

	t.Run("jwt_without_exp_softpasses", func(t *testing.T) {
		t.Parallel()
		tok := jwtWithClaims(t, map[string]interface{}{"sub": "u-1"})
		gotExp, isJWT := unverifiedExp(tok)
		require.True(t, isJWT)
		require.Zero(t, gotExp)
		require.False(t, srv.OAuthTokenExpired(tok))
	})

	t.Run("exp_as_float_parsed", func(t *testing.T) {
		t.Parallel()
		// json numbers can decode as float; ensure fractional exp still works.
		raw := time.Now().Add(-time.Hour).Unix()
		tok := "header." + base64.RawURLEncoding.EncodeToString(
			[]byte(fmt.Sprintf(`{"exp":%d.5}`, raw))) + ".sig"
		gotExp, isJWT := unverifiedExp(tok)
		require.True(t, isJWT)
		require.Equal(t, raw, gotExp)
		require.True(t, srv.OAuthTokenExpired(tok))
	})

	t.Run("malformed_payload_softpasses", func(t *testing.T) {
		t.Parallel()
		_, isJWT := unverifiedExp("head.!!notbase64!!.sig")
		require.False(t, isJWT)
	})
}
