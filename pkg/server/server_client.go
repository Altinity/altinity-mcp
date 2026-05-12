package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
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

// GetOAuthClaimsFromCtx extracts OAuth claims from context
func (s *ClickHouseJWEServer) GetOAuthClaimsFromCtx(ctx context.Context) *OAuthClaims {
	if claims := ctx.Value(OAuthClaimsKey); claims != nil {
		if oauthClaims, ok := claims.(*OAuthClaims); ok {
			return oauthClaims
		}
	}
	return nil
}

// BuildClickHouseHeadersFromOAuth builds HTTP headers to forward to ClickHouse based on OAuth config
func (s *ClickHouseJWEServer) BuildClickHouseHeadersFromOAuth(token string, claims *OAuthClaims) map[string]string {
	if !s.Config.Server.OAuth.IsForwardMode() {
		return nil
	}

	headers := make(map[string]string)

	// Forward the access token (always in forward mode)
	headerName := s.Config.Server.OAuth.ClickHouseHeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	if headerName == "Authorization" {
		headers[headerName] = "Bearer " + token
	} else {
		headers[headerName] = token
	}

	// Map claims to headers if configured
	if len(s.Config.Server.OAuth.ClaimsToHeaders) > 0 && claims != nil {
		for claimName, headerName := range s.Config.Server.OAuth.ClaimsToHeaders {
			var value string
			switch claimName {
			case "sub":
				value = claims.Subject
			case "iss":
				value = claims.Issuer
			case "email":
				value = claims.Email
			case "name":
				value = claims.Name
			case "email_verified":
				if claims.EmailVerified {
					value = "true"
				} else {
					value = "false"
				}
			case "hd":
				value = claims.HostedDomain
			default:
				// Check extra claims
				if v, ok := claims.Extra[claimName]; ok {
					if strVal, ok := v.(string); ok {
						value = strVal
					} else {
						// Try to JSON encode non-string values
						if jsonBytes, err := json.Marshal(v); err == nil {
							value = string(jsonBytes)
						}
					}
				}
			}
			if value != "" {
				headers[headerName] = value
			}
		}
	}

	return headers
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

	// Fall through to OAuth
	if oauthEnabled {
		oauthToken = s.ExtractOAuthTokenFromRequest(r)
		if oauthToken == "" {
			return jweToken, jweClaims, "", nil, ErrMissingOAuthToken
		}
		if s.oauthRequiresLocalValidation() {
			oauthClaims, err = s.ValidateOAuthToken(oauthToken)
			if err != nil {
				return jweToken, jweClaims, "", nil, err
			}
		}
		return jweToken, jweClaims, oauthToken, oauthClaims, nil
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

	// Add OAuth headers if forwarding is enabled
	if s.Config.Server.OAuth.IsForwardMode() && oauthToken != "" {
		oauthHeaders := s.BuildClickHouseHeadersFromOAuth(oauthToken, oauthClaims)
		if len(oauthHeaders) > 0 {
			if chConfig.HttpHeaders == nil {
				chConfig.HttpHeaders = make(map[string]string)
			}
			for k, v := range oauthHeaders {
				chConfig.HttpHeaders[k] = v
			}
		}
		// In forward mode, always clear static credentials — ClickHouse authenticates via the token
		chConfig.Username = ""
		chConfig.Password = ""
	}

	// In cluster-secret mode, the shared secret is the only credential sent
	// to ClickHouse; Username is just the identity we ask ClickHouse to
	// impersonate. When OAuth is enabled, prefer the authenticated user's
	// email so `system.query_log` attributes the query to a human-readable
	// identity that matches how operators typically provision ClickHouse
	// users.
	//
	// Auth0 enhanced-security third-party (DCR) tokens strip the OIDC `email`
	// claim from access tokens. Operators work around this with a post-login
	// Action that re-adds email under a namespaced URL claim (Auth0 only
	// allows non-standard claims when they're URL-prefixed for third-party
	// clients). We accept either the standard `email` claim or any namespaced
	// `*/email` claim from the Extra map. Fall back to `sub` for IdPs that
	// don't emit any email claim.
	if chConfig.ClusterSecret != "" && oauthClaims != nil {
		var impersonateAs string
		if e := strings.TrimSpace(oauthClaims.Email); e != "" {
			impersonateAs = e
		} else if e := emailFromNamespacedExtra(oauthClaims.Extra); e != "" {
			impersonateAs = e
		} else if s := strings.TrimSpace(oauthClaims.Subject); s != "" {
			impersonateAs = s
		}
		if impersonateAs != "" {
			chConfig.Username = impersonateAs
		}
		chConfig.Password = ""
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

// emailFromNamespacedExtra returns the first string-valued claim whose key
// ends with `/email` from the JWT's non-standard claim map. Auth0 third-party
// (DCR) tokens in enhanced security mode silently drop non-namespaced custom
// claims, forcing operators to set email under a URL-prefixed key (e.g.
// `https://mcp.altinity.cloud/email`). Looking up by suffix lets MCP accept
// any namespace the operator chose.
func emailFromNamespacedExtra(extra map[string]interface{}) string {
	for k, v := range extra {
		if !strings.HasSuffix(k, "/email") {
			continue
		}
		if s, ok := v.(string); ok {
			if t := strings.TrimSpace(s); t != "" {
				return t
			}
		}
	}
	return ""
}
