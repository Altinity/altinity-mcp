package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/go-mcp-oauth-sdk/jwe_auth"
	"github.com/altinity/go-mcp-oauth-sdk/oauth"
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

// buildConfigFromClaims builds a ClickHouse config from JWE claims.
// In multi-cluster mode the caller passes a base config whose Host has
// already been template-expanded for the active cluster; we do not reach
// for s.Config.ClickHouse so the per-request cluster routing is preserved.
func (s *ClickHouseJWEServer) buildConfigFromClaims(claims map[string]interface{}) (config.ClickHouseConfig, error) {
	return s.buildConfigFromClaimsWithBase(s.Config.ClickHouse, claims)
}

// buildConfigFromClaimsWithBase is the explicit-base variant used by the
// multi-cluster path. Same body as buildConfigFromClaims but takes the base
// chCfg as a parameter so the global is never consulted on the hot path.
func (s *ClickHouseJWEServer) buildConfigFromClaimsWithBase(base config.ClickHouseConfig, claims map[string]interface{}) (config.ClickHouseConfig, error) {
	chConfig := base // copy

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

// GetClickHouseClientFromCtx creates a ClickHouse client using JWE and/or
// OAuth tokens from context. When the multi-cluster router has injected a
// per-request ClickHouseConfig (host templated for the active cluster), it
// is used; otherwise s.Config.ClickHouse is the base.
func (s *ClickHouseJWEServer) GetClickHouseClientFromCtx(ctx context.Context) (*clickhouse.Client, error) {
	jweToken := s.ExtractTokenFromCtx(ctx)
	oauthToken := s.ExtractOAuthTokenFromCtx(ctx)
	oauthClaims := s.GetOAuthClaimsFromCtx(ctx)
	chCfg := CHConfigFromContext(ctx, s.Config.ClickHouse)
	return s.GetClickHouseClientWithOAuthForConfig(ctx, chCfg, jweToken, oauthToken, oauthClaims)
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

	// Fall through to OAuth. ClickHouse or its sidecar cryptographically
	// validates the JWT at each query, so MCP does not re-validate here.
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

// GetClickHouseClientWithOAuth creates a ClickHouse client using OAuth bearer
// credentials when present. Uses the global s.Config.ClickHouse as the base.
// The multi-cluster path calls GetClickHouseClientWithOAuthForConfig instead,
// threading a per-request chCfg through so per-cluster host templating is
// preserved.
func (s *ClickHouseJWEServer) GetClickHouseClientWithOAuth(ctx context.Context, jweToken string, oauthToken string, oauthClaims *OAuthClaims) (*clickhouse.Client, error) {
	return s.GetClickHouseClientWithOAuthForConfig(ctx, s.Config.ClickHouse, jweToken, oauthToken, oauthClaims)
}

// GetClickHouseClientWithOAuthForConfig is the chCfg-explicit variant of
// GetClickHouseClientWithOAuth. The caller is responsible for supplying a
// ClickHouseConfig whose Host has already been template-expanded for the
// active cluster. The global s.Config.ClickHouse is not consulted on a
// per-request hot path under this entry point — single-cluster callers
// route here too via the no-arg shim above.
func (s *ClickHouseJWEServer) GetClickHouseClientWithOAuthForConfig(ctx context.Context, chCfg config.ClickHouseConfig, jweToken string, oauthToken string, oauthClaims *OAuthClaims) (*clickhouse.Client, error) {
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
		chConfig, err = s.buildConfigFromClaimsWithBase(chCfg, claims)
		if err != nil {
			return nil, err
		}
	} else {
		chConfig = chCfg
	}

	// Merge tool-input settings before OAuth so probe configs carry them.
	if toolSettings := ToolInputSettingsFromContext(ctx); len(toolSettings) > 0 {
		chConfig = mergeExtraSettings(chConfig, toolSettings)
	}

	if s.Config.Server.OAuth.Enabled && oauthToken != "" {
		if claimName := strings.TrimSpace(s.Config.Server.OAuth.RoleClaim); claimName != "" {
			roles := oauth.RolesFromClaim(oauthClaims, claimName, s.roleFilter())
			if len(roles) == 0 {
				// Fail closed: an empty filtered set must NOT fall back to the
				// user's default (full) grant. Reject the request.
				return nil, fmt.Errorf("oauth: access denied — no ClickHouse roles in claim %q matched role_filter", claimName)
			}
			if chConfig.Protocol != config.HTTPProtocol {
				// role= activation is an HTTP-interface feature; silently
				// dropping it on TCP would run the request with the full grant
				// (fail open), so refuse instead.
				return nil, fmt.Errorf("oauth: role activation requires clickhouse protocol http, got %q", chConfig.Protocol)
			}
			chConfig.Roles = roles
		}
		return s.newClientWithOAuth(ctx, chConfig, oauthToken)
	}

	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
	}
	return client, nil
}

// chOAuthMethod is the wire format used to authenticate against ClickHouse.
type chOAuthMethod int8

const (
	chOAuthMethodBearer chOAuthMethod = 1 // Authorization: Bearer <token>
	chOAuthMethodBasic  chOAuthMethod = 2 // Authorization: Basic base64(email:token)
)

// newClientWithOAuth resolves the CH auth method for the endpoint (from cache
// or by probing), then creates and returns a connected ClickHouse client.
//
// The method is auto-detected by trying Bearer first; on CH auth error it
// falls back to Basic and caches the result so subsequent requests skip the
// probe.
func (s *ClickHouseJWEServer) newClientWithOAuth(ctx context.Context, chCfg config.ClickHouseConfig, token string) (*clickhouse.Client, error) {
	cfg := s.Config.Server.OAuth
	endpoint := fmt.Sprintf("%s:%d", chCfg.Host, chCfg.Port)

	// Cache hit — use the stored method. chCfg carries any per-request roles,
	// which newClientForOAuthMethod applies via the CH client.
	if v, ok := s.chOAuthMethodCache.Load(endpoint); ok {
		return newClientForOAuthMethod(ctx, chCfg, token, v.(chOAuthMethod), cfg)
	}

	// Auto-detect the CH auth wire format with a ROLE-FREE probe. A role the
	// user isn't granted makes CH return ACCESS_DENIED (code 497), which
	// isChAuthError treats as an auth failure — on a role-carrying probe that
	// would be misread as "Bearer rejected" and trigger a spurious Basic
	// fallback. Probing without roles keeps the auth-method signal clean; the
	// detected method then builds the real, role-carrying client below.
	probeCfg := chCfg
	probeCfg.Roles = nil

	// Try Bearer first. NewClient pings internally, so a failed ping surfaces
	// as an auth error here if CH rejects the token.
	bearerCfg := oauthApplyBearer(probeCfg, token, cfg)
	if client, err := clickhouse.NewClient(ctx, bearerCfg); err == nil {
		s.chOAuthMethodCache.Store(endpoint, chOAuthMethodBearer)
		if len(chCfg.Roles) == 0 {
			return client, nil // no roles — reuse the probe client, no second ping
		}
		_ = client.Close()
		return newClientForOAuthMethod(ctx, chCfg, token, chOAuthMethodBearer, cfg)
	} else if !isChAuthError(err) {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
	}

	// Bearer got an auth error — try Basic (ch-jwt-verify sidecar path).
	log.Debug().Str("endpoint", endpoint).Msg("oauth: Bearer rejected by CH, probing Basic")
	email, ok := emailFromUnverifiedJWT(token)
	if !ok {
		return nil, fmt.Errorf("oauth: bearer is not a JWT with an email claim")
	}
	basicCfg := oauthApplyBasic(probeCfg, email, token)
	client, err := clickhouse.NewClient(ctx, basicCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
	}
	s.chOAuthMethodCache.Store(endpoint, chOAuthMethodBasic)
	if len(chCfg.Roles) == 0 {
		return client, nil
	}
	_ = client.Close()
	return newClientForOAuthMethod(ctx, chCfg, token, chOAuthMethodBasic, cfg)
}

// newClientForOAuthMethod applies method to chCfg and creates a CH client.
func newClientForOAuthMethod(ctx context.Context, chCfg config.ClickHouseConfig, token string, method chOAuthMethod, oauthCfg oauth.OAuthConfig) (*clickhouse.Client, error) {
	switch method {
	case chOAuthMethodBearer:
		chCfg = oauthApplyBearer(chCfg, token, oauthCfg)
	case chOAuthMethodBasic:
		email, ok := emailFromUnverifiedJWT(token)
		if !ok {
			return nil, fmt.Errorf("oauth: bearer is not a JWT with an email claim")
		}
		chCfg = oauthApplyBasic(chCfg, email, token)
	}
	client, err := clickhouse.NewClient(ctx, chCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
	}
	return client, nil
}

// oauthApplyBearer returns a copy of chCfg with an Authorization: Bearer header set.
func oauthApplyBearer(chCfg config.ClickHouseConfig, token string, oauthCfg oauth.OAuthConfig) config.ClickHouseConfig {
	headers := oauth.BuildClickHouseHeaders(oauthCfg, token)
	if len(headers) > 0 {
		if chCfg.HttpHeaders == nil {
			chCfg.HttpHeaders = make(map[string]string)
		}
		for k, v := range headers {
			chCfg.HttpHeaders[k] = v
		}
	}
	chCfg.Username = ""
	chCfg.Password = ""
	return chCfg
}

// oauthApplyBasic returns a copy of chCfg with Basic auth credentials set.
// CH's http_authentication extension expects Basic base64(email:JWT) and
// delegates validation to the ch-jwt-verify sidecar over loopback.
func oauthApplyBasic(chCfg config.ClickHouseConfig, email, token string) config.ClickHouseConfig {
	chCfg.Username = email
	chCfg.Password = token
	chCfg.Protocol = config.HTTPProtocol
	return chCfg
}

// isChAuthError reports whether err is a CH authentication failure.
// Delegates to ClassifyDiscoveryError (multicluster_identity.go) which covers
// HTTP 401/403, CH exception codes 497/516/519, and common error strings.
func isChAuthError(err error) bool {
	auth, _ := ClassifyDiscoveryError(err)
	return auth
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
			log.Debug().Err(err).Msg("oauth: failed to base64-decode JWT payload")
			return "", false
		}
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		log.Debug().Err(err).Msg("oauth: failed to JSON-parse JWT payload")
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

// oauthExpiryClockSkewSecs tolerates small clock differences between this
// server and the IdP that signed the token so a token expiring within seconds
// does not bounce clients with slightly fast clocks.
const oauthExpiryClockSkewSecs = 60

// unverifiedExp decodes the JWT payload WITHOUT verifying the signature and
// returns the `exp` claim. isJWT is false for anything that is not a
// three-segment JWT with a decodable payload (opaque tokens, malformed input) —
// callers treat that as "cannot tell, soft-pass". Crypto validation (signature,
// iss, aud, scope) stays delegated to the CH-side ch-jwt-verify sidecar per
// query; this only catches the expiry case so the MCP transport can return a
// 401 on tools/list instead of letting an expired session linger as stale tools.
func unverifiedExp(token string) (exp int64, isJWT bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some IdPs emit padded segments; try the std encoding as a fallback.
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			log.Debug().Err(err).Msg("oauth: failed to base64-decode JWT payload for exp")
			return 0, false
		}
	}
	var raw struct {
		Exp json.Number `json:"exp"`
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		log.Debug().Err(err).Msg("oauth: failed to JSON-parse JWT payload for exp")
		return 0, false
	}
	if raw.Exp == "" {
		// Valid JWT but no exp claim — nothing to expire on.
		return 0, true
	}
	v, err := raw.Exp.Int64()
	if err != nil {
		// exp present but non-numeric/float; fall back to float parse.
		f, ferr := raw.Exp.Float64()
		if ferr != nil {
			log.Debug().Err(err).Msg("oauth: JWT exp claim is not numeric")
			return 0, true
		}
		v = int64(f)
	}
	return v, true
}

// OAuthTokenExpired reports whether token is a JWT whose `exp` claim is in the
// past (with clock skew). Opaque/non-JWT tokens and JWTs without an exp claim
// return false (soft-pass) so forward-mode and opaque-token deployments keep
// working unchanged. Signature is NOT verified — see unverifiedExp.
func (s *ClickHouseJWEServer) OAuthTokenExpired(token string) bool {
	exp, isJWT := unverifiedExp(token)
	if !isJWT || exp <= 0 {
		return false
	}
	return time.Now().Unix() > exp+oauthExpiryClockSkewSecs
}
