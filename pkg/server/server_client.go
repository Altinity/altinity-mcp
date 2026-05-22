package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/altinity/altinity-mcp/pkg/oauth"
	"github.com/rs/zerolog/log"
)

// GetClickHouseClient creates a ClickHouse client from JWE token or falls back to default config.
func (s *ClickHouseJWEServer) GetClickHouseClient(ctx context.Context, tokenParam string) (*clickhouse.Client, error) {
	var chConfig config.ClickHouseConfig

	if !s.Config.Server.JWE.Enabled {
		chConfig = s.Config.ClickHouse
	} else {
		if tokenParam == "" {
			// JWE auth is enabled but no token provided
			return nil, jwe_auth.ErrMissingToken
		}

		// Parse and validate JWE token
		claims, err := jwe_auth.ParseAndDecryptJWE(tokenParam, []byte(s.Config.Server.JWE.JWESecretKey), []byte(s.Config.Server.JWE.JWTSecretKey))
		if err != nil {
			log.Error().Err(err).Msg("failed to parse/decrypt JWE token")
			return nil, err
		}

		var buildErr error
		// Create ClickHouse config from JWE claims
		chConfig, buildErr = s.buildConfigFromClaims(claims)
		if buildErr != nil {
			return nil, buildErr
		}
	}

	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
	}

	return client, nil
}

// buildConfigFromClaims builds a ClickHouse config from JWE claims
func (s *ClickHouseJWEServer) buildConfigFromClaims(claims map[string]interface{}) (config.ClickHouseConfig, error) {
	// Create a new ClickHouse config from the claims
	chConfig := s.Config.ClickHouse // Use default as base

	if host, ok := claims["host"].(string); ok && host != "" {
		chConfig.Host = host
	}
	if port, ok := claims["port"].(float64); ok && port > 0 {
		chConfig.Port = int(port)
	}
	if database, ok := claims["database"].(string); ok && database != "" {
		chConfig.Database = database
	}
	if username, ok := claims["username"].(string); ok && username != "" {
		chConfig.Username = username
	}
	if password, ok := claims["password"].(string); ok && password != "" {
		chConfig.Password = password
	}
	if protocol, ok := claims["protocol"].(string); ok && protocol != "" {
		chConfig.Protocol = config.ClickHouseProtocol(protocol)
	}
	if limit, ok := claims["limit"].(float64); ok && limit > 0 {
		chConfig.Limit = int(limit)
	}

	// Handle TLS configuration from JWE claims
	if tlsEnabled, ok := claims["tls_enabled"].(bool); ok && tlsEnabled {
		chConfig.TLS.Enabled = true

		if caCert, ok := claims["tls_ca_cert"].(string); ok && caCert != "" {
			chConfig.TLS.CaCert = caCert
		}
		if clientCert, ok := claims["tls_client_cert"].(string); ok && clientCert != "" {
			chConfig.TLS.ClientCert = clientCert
		}
		if clientKey, ok := claims["tls_client_key"].(string); ok && clientKey != "" {
			chConfig.TLS.ClientKey = clientKey
		}
		if insecureSkipVerify, ok := claims["tls_insecure_skip_verify"].(bool); ok {
			chConfig.TLS.InsecureSkipVerify = insecureSkipVerify
		}
	}

	return chConfig, nil
}

// GetClickHouseClientFromCtx creates a ClickHouse client using JWE and/or OAuth tokens from context
func (s *ClickHouseJWEServer) GetClickHouseClientFromCtx(ctx context.Context) (*clickhouse.Client, error) {
	jweToken := s.ExtractTokenFromCtx(ctx)
	oauthToken := s.ExtractOAuthTokenFromCtx(ctx)
	oauthClaims := s.GetOAuthClaimsFromCtx(ctx)
	return s.GetClickHouseClientWithOAuth(ctx, jweToken, oauthToken, oauthClaims)
}

// GetJWEClaimsFromCtx extracts parsed JWE claims from context.
func (s *ClickHouseJWEServer) GetJWEClaimsFromCtx(ctx context.Context) map[string]interface{} {
	if claims := ctx.Value(JWEClaimsKey); claims != nil {
		if jweClaims, ok := claims.(map[string]interface{}); ok {
			return jweClaims
		}
	}
	return nil
}

// GetOAuthClaimsFromCtx extracts OAuth claims from context. Delegates to
// the pkg/oauth context helper; preserved for callers/tests that hold a
// *ClickHouseJWEServer rather than reaching for pkg/oauth directly.
func (s *ClickHouseJWEServer) GetOAuthClaimsFromCtx(ctx context.Context) *OAuthClaims {
	return oauth.ClaimsFromContext(ctx)
}

// ValidateAuth validates authentication using priority/fallback semantics.
// JWE takes priority: if present and valid with credentials, OAuth is skipped.
// If JWE is absent or has no credentials, falls through to OAuth.
func (s *ClickHouseJWEServer) ValidateAuth(r *http.Request) (jweToken string, jweClaims map[string]interface{}, oauthToken string, oauthClaims *OAuthClaims, err error) {
	jweEnabled := s.Config.Server.JWE.Enabled
	oauthEnabled := s.Config.Server.OAuth.Enabled

	// If neither auth method is enabled, no validation needed
	if !jweEnabled && !oauthEnabled {
		return "", nil, "", nil, nil
	}

	// Try JWE first
	if jweEnabled {
		if oauthEnabled {
			// When OAuth is also enabled, only extract JWE from unambiguous sources
			// (path value / x-altinity-mcp-key) to avoid conflicting with OAuth Bearer.
			jweToken = r.PathValue("token")
			if jweToken == "" {
				jweToken = r.Header.Get("x-altinity-mcp-key")
			}
		} else {
			jweToken = s.ExtractTokenFromRequest(r)
		}
		if jweToken != "" {
			jweClaims, err = s.ParseJWEClaims(jweToken)
			if err != nil {
				return "", nil, "", nil, err // JWE present but invalid → hard error
			}
			if s.JWEClaimsHaveCredentials(jweClaims) {
				return jweToken, jweClaims, "", nil, nil // JWE sufficient, skip OAuth
			}
		}
	}

	// Fall through to OAuth. MCP is a pure forwarder for queries: the
	// ch-jwt-verify sidecar cryptographically validates the JWT at each
	// ClickHouse query, so MCP does not re-validate here.
	if oauthEnabled {
		oauthToken = s.ExtractOAuthTokenFromRequest(r)
		if oauthToken == "" {
			return jweToken, jweClaims, "", nil, ErrMissingOAuthToken
		}
		return jweToken, jweClaims, oauthToken, nil, nil
	}

	// JWE enabled but no token and no OAuth
	if jweEnabled && jweToken == "" {
		return "", nil, "", nil, jwe_auth.ErrMissingToken
	}

	return jweToken, jweClaims, "", nil, nil
}

func (s *ClickHouseJWEServer) openAPIPathPrefixes() []string {
	if s.Config.Server.JWE.Enabled {
		prefixes := []string{"/{jwe_token}"}
		if s.Config.Server.OAuth.Enabled {
			prefixes = append(prefixes, "")
		}
		return prefixes
	}
	return []string{""}
}

// GetClickHouseClientWithOAuth creates a ClickHouse client, optionally forwarding OAuth headers
func (s *ClickHouseJWEServer) GetClickHouseClientWithOAuth(ctx context.Context, jweToken string, oauthToken string, oauthClaims *OAuthClaims) (*clickhouse.Client, error) {
	// Build base config
	var chConfig config.ClickHouseConfig
	var err error

	// If JWE is enabled and token provided, use JWE config
	if s.Config.Server.JWE.Enabled && jweToken != "" {
		claims := s.GetJWEClaimsFromCtx(ctx)
		if claims == nil {
			claims, err = s.ParseJWEClaims(jweToken)
			if err != nil {
				return nil, fmt.Errorf("failed to parse JWE token: %w", err)
			}
		}
		chConfig, err = s.buildConfigFromClaims(claims)
		if err != nil {
			return nil, err
		}
	} else {
		chConfig = s.Config.ClickHouse
	}

	// Switch on OAuth mode to pick the CH wire format. Forward and gating
	// both apply only when an OAuth bearer is on the inbound request.
	if s.Config.Server.OAuth.Enabled && oauthToken != "" {
		switch {
		case s.Config.Server.OAuth.IsForwardMode():
			// Forward mode: rewrite the Authorization header so ClickHouse
			// receives `Bearer <token>` directly. Antalya's token_processors
			// validates the bearer cryptographically.
			oauthHeaders := oauth.BuildClickHouseHeaders(s.Config.Server.OAuth, oauthToken, oauthClaims)
			if len(oauthHeaders) > 0 {
				if chConfig.HttpHeaders == nil {
					chConfig.HttpHeaders = make(map[string]string)
				}
				for k, v := range oauthHeaders {
					chConfig.HttpHeaders[k] = v
				}
			}
			chConfig.Username = ""
			chConfig.Password = ""
		case s.Config.Server.OAuth.IsGatingMode():
			// Gating mode: ClickHouse's <http_authentication> calls the
			// colocated ch-jwt-verify sidecar over loopback to validate the
			// JWT. The CH driver assembles `Authorization: Basic
			// base64(email:JWT)` from Username/Password. The email is
			// unverified-decoded from the JWT here; the sidecar enforces
			// signature/iss/aud/exp/scope and the user-vs-email match.
			email, ok := emailFromUnverifiedJWT(oauthToken)
			if !ok {
				return nil, fmt.Errorf("oauth gating: bearer is not a JWT with an email claim")
			}
			chConfig.Username = email
			chConfig.Password = oauthToken
			// http_authentication is HTTP-only on the CH side. Force the
			// driver to use HTTP regardless of static config.
			chConfig.Protocol = config.HTTPProtocol
		}
	}

	// Merge tool-input settings from context (tool_input_settings)
	if toolSettings := ToolInputSettingsFromContext(ctx); len(toolSettings) > 0 {
		chConfig = mergeExtraSettings(chConfig, toolSettings)
	}

	// Create client
	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
	}

	return client, nil
}

// emailFromUnverifiedJWT decodes the JWT payload without verifying the
// signature and returns the `email` claim (or first namespaced `*/email`
// fallback). Used only to populate the CH `Basic` username so the sidecar can
// receive it; the sidecar still verifies the JWT signature and rejects any
// mismatch between the JWT's signed email and the Basic user.
func emailFromUnverifiedJWT(token string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some IdPs emit padded segments; try the std encoding as a fallback.
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			log.Debug().Err(err).Msg("oauth gating: failed to base64-decode JWT payload")
			return "", false
		}
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		log.Debug().Err(err).Msg("oauth gating: failed to JSON-parse JWT payload")
		return "", false
	}
	if e, ok := raw["email"].(string); ok {
		if t := strings.TrimSpace(e); t != "" {
			return t, true
		}
	}
	if e := oauth.EmailFromNamespacedExtra(raw); e != "" {
		return e, true
	}
	return "", false
}
