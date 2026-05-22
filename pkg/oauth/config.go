package oauth

import "strings"

// OAuthConfig defines configuration for OAuth 2.0 authentication.
//
// Every flag-tagged field is settable via CLI flag (`flag:` tag) or env var
// (`env:` tag). The env-var convention here is `MCP_OAUTH_<UPPER_SNAKE>` so
// secrets like SigningSecret can be injected from a Kubernetes Secret via
// the Helm chart's env: array using valueFrom.secretKeyRef.
type OAuthConfig struct {
	// Mode controls whether altinity-mcp forwards external OAuth bearers or gates them into local MCP tokens.
	// "forward" is the production path: pass the end-user bearer through to ClickHouse.
	// "gating" keeps the built-in limited OAuth facade that issues its own tokens.
	Mode string `json:"mode" yaml:"mode" flag:"oauth-mode" env:"MCP_OAUTH_MODE" desc:"OAuth operating mode (forward/gating)"`

	// Enabled enables OAuth authentication
	Enabled bool `json:"enabled" yaml:"enabled" flag:"oauth-enabled" env:"MCP_OAUTH_ENABLED" desc:"Enable OAuth 2.0 authentication"`

	// Issuer is the OAuth token issuer URL for token validation (e.g., "https://accounts.google.com")
	Issuer string `json:"issuer" yaml:"issuer" flag:"oauth-issuer" env:"MCP_OAUTH_ISSUER" desc:"OAuth token issuer URL for validation"`

	// JWKSURL is the URL to fetch JSON Web Key Set for token validation
	// If empty, will be discovered from issuer's .well-known/openid-configuration
	JWKSURL string `json:"jwks_url" yaml:"jwks_url" flag:"oauth-jwks-url" env:"MCP_OAUTH_JWKS_URL" desc:"URL to fetch JWKS for token validation"`

	// Audience is the expected audience claim in the token
	Audience string `json:"audience" yaml:"audience" flag:"oauth-audience" env:"MCP_OAUTH_AUDIENCE" desc:"Expected audience claim in OAuth token"`

	// PublicResourceURL is the externally visible protected resource base URL.
	// When empty, it is inferred from the request host/prefix or Audience path.
	PublicResourceURL string `json:"public_resource_url" yaml:"public_resource_url" flag:"oauth-public-resource-url" env:"MCP_OAUTH_PUBLIC_RESOURCE_URL" desc:"Externally visible protected resource base URL"`

	// PublicAuthServerURL is the externally visible authorization server base URL.
	// When empty, it is inferred from the request host/prefix or Issuer path.
	PublicAuthServerURL string `json:"public_auth_server_url" yaml:"public_auth_server_url" flag:"oauth-public-auth-server-url" env:"MCP_OAUTH_PUBLIC_AUTH_SERVER_URL" desc:"Externally visible OAuth authorization server base URL"`

	// ClientID is the OAuth client ID (used for client credentials flow or validation)
	ClientID string `json:"client_id" yaml:"client_id" flag:"oauth-client-id" env:"MCP_OAUTH_CLIENT_ID" desc:"OAuth client ID"`

	// ClientSecret is the OAuth client secret (used for client credentials flow)
	ClientSecret string `json:"client_secret" yaml:"client_secret" flag:"oauth-client-secret" env:"MCP_OAUTH_CLIENT_SECRET" desc:"OAuth client secret"`

	// TokenURL is the OAuth token endpoint URL (used for client credentials flow)
	TokenURL string `json:"token_url" yaml:"token_url" flag:"oauth-token-url" env:"MCP_OAUTH_TOKEN_URL" desc:"OAuth token endpoint URL"`

	// AuthURL is the OAuth authorization endpoint URL (used for authorization code flow)
	AuthURL string `json:"auth_url" yaml:"auth_url" flag:"oauth-auth-url" env:"MCP_OAUTH_AUTH_URL" desc:"OAuth authorization endpoint URL"`

	// UserInfoURL is the upstream OpenID Connect userinfo endpoint URL.
	// If empty, it will be discovered from issuer metadata when needed.
	UserInfoURL string `json:"userinfo_url" yaml:"userinfo_url" flag:"oauth-userinfo-url" env:"MCP_OAUTH_USERINFO_URL" desc:"OAuth/OpenID Connect userinfo endpoint URL"`

	// Scopes is the list of OAuth scopes to request
	Scopes []string `json:"scopes" yaml:"scopes" flag:"oauth-scopes" env:"MCP_OAUTH_SCOPES" desc:"OAuth scopes to request"`

	// UpstreamOfflineAccess opts forward/broker mode into appending
	// `offline_access` to the scope sent upstream. Used mainly so the IdP's
	// consent screen offers long-lived sessions; the upstream refresh token
	// MCP receives is currently discarded. v1 issues NO downstream refresh
	// tokens to CIMD clients — they re-authorize via /oauth/authorize when
	// the access token expires. See #115 § Refresh-token policy.
	// Default false. Effect is upstream-only; this flag does not turn on
	// any downstream refresh-token issuance.
	UpstreamOfflineAccess bool `json:"upstream_offline_access" yaml:"upstream_offline_access" flag:"oauth-upstream-offline-access" env:"MCP_OAUTH_UPSTREAM_OFFLINE_ACCESS" desc:"Append offline_access to the upstream scope so the IdP's consent screen offers long-lived sessions. v1 does NOT issue downstream refresh tokens regardless of this flag — clients re-authorize via /oauth/authorize."`

	// UpstreamForceConsent forces `prompt=consent` on every upstream
	// /authorize call (Google-family providers only). The first authorize
	// for a user with `upstream_offline_access: true` always triggers the
	// consent screen anyway — Google mints the refresh_token there and
	// remembers it. Subsequent silent-SSO redemptions reuse the existing
	// grant without re-prompting. Set this to true only when the operator
	// needs to force re-enrollment (e.g. after rotating the upstream OAuth
	// client). Default false avoids the surprise re-consent on every login.
	UpstreamForceConsent bool `json:"upstream_force_consent" yaml:"upstream_force_consent" flag:"oauth-upstream-force-consent" env:"MCP_OAUTH_UPSTREAM_FORCE_CONSENT" desc:"Force prompt=consent on every upstream /authorize (Google providers only). Default false reuses Google's stored offline-access grant after the first consent."`

	// BrokerUpstream opts gating mode into the DCR-via-MCP broker pattern that
	// forward mode uses by default. When true under gating mode, altinity-mcp:
	//   - Acts as the OAuth AS to claude.ai/ChatGPT (hosts /oauth/{register,
	//     authorize,callback,token}, mints stateless DCR client_ids).
	//   - Brokers an upstream IdP using a static OAuth application
	//     (ClientID/ClientSecret/AuthURL/TokenURL config).
	//   - Returns the upstream id_token unchanged as the access_token to the
	//     MCP-client; on /mcp the gating-mode JWKS-validation path validates
	//     it against the upstream issuer's JWKS and impersonates the user to
	//     ClickHouse via cluster_secret + Auth.Username.
	// This is the same shape as forward mode minus the JWT-passthrough-to-CH:
	// CH is reached via interserver auth + email impersonation as in standard
	// gating mode. Use when the upstream IdP does not support CIMD natively
	// (e.g. Google directly) but you don't want to expose CH to per-query JWT
	// validation. Default false: gating remains pure resource server (#109).
	BrokerUpstream bool `json:"broker_upstream" yaml:"broker_upstream" flag:"oauth-broker-upstream" env:"MCP_OAUTH_BROKER_UPSTREAM" desc:"Gating mode: enable DCR-via-MCP broker pattern (act as AS to clients, broker upstream IdP). Requires client_id/client_secret/auth_url/token_url/issuer to be set."`

	// RequiredScopes is the list of scopes required for access (token must have all of these)
	RequiredScopes []string `json:"required_scopes" yaml:"required_scopes" flag:"oauth-required-scopes" env:"MCP_OAUTH_REQUIRED_SCOPES" desc:"Required OAuth scopes for access"`

	// ClickHouseHeaderName is the header name to use when forwarding OAuth token to ClickHouse
	// Default: "Authorization" (sends as "Bearer {token}")
	// When set to a custom header, the raw token is sent without "Bearer " prefix
	ClickHouseHeaderName string `json:"clickhouse_header_name" yaml:"clickhouse_header_name" flag:"oauth-clickhouse-header-name" env:"MCP_OAUTH_CLICKHOUSE_HEADER_NAME" desc:"Header name for forwarding OAuth token to ClickHouse"`

	// ClaimsToHeaders maps OAuth token claims to ClickHouse HTTP headers
	// Example: {"sub": "X-ClickHouse-User", "email": "X-ClickHouse-Email"}
	ClaimsToHeaders map[string]string `json:"claims_to_headers" yaml:"claims_to_headers" flag:"oauth-claims-to-headers" env:"MCP_OAUTH_CLAIMS_TO_HEADERS" desc:"Map OAuth claims to ClickHouse HTTP headers"`

	// AllowedEmailDomains constrains accepted principals by email domain.
	AllowedEmailDomains []string `json:"allowed_email_domains" yaml:"allowed_email_domains" flag:"oauth-allowed-email-domains" env:"MCP_OAUTH_ALLOWED_EMAIL_DOMAINS" desc:"Allowed email domains for verified OAuth identities"`

	// AllowedHostedDomains constrains accepted principals by hosted/workspace domain claim such as Google hd.
	AllowedHostedDomains []string `json:"allowed_hosted_domains" yaml:"allowed_hosted_domains" flag:"oauth-allowed-hosted-domains" env:"MCP_OAUTH_ALLOWED_HOSTED_DOMAINS" desc:"Allowed hosted/workspace domains for verified OAuth identities"`

	// AllowUnverifiedEmail opts out of the email_verified=true requirement.
	// Default zero value (false) rejects tokens carrying email with email_verified=false.
	// Set true only when the IdP omits email_verified or the operator trusts upstream verification.
	AllowUnverifiedEmail bool `json:"allow_unverified_email" yaml:"allow_unverified_email" flag:"oauth-allow-unverified-email" env:"MCP_OAUTH_ALLOW_UNVERIFIED_EMAIL" desc:"Accept OAuth identities with email_verified=false (default: reject)"`

	// AuthorizationPath configures the relative path for the authorization endpoint.
	AuthorizationPath string `json:"authorization_path" yaml:"authorization_path" flag:"oauth-authorization-path" env:"MCP_OAUTH_AUTHORIZATION_PATH" desc:"Relative path for OAuth authorization endpoint"`

	// CallbackPath configures the relative path for the upstream IdP callback handler.
	CallbackPath string `json:"callback_path" yaml:"callback_path" flag:"oauth-callback-path" env:"MCP_OAUTH_CALLBACK_PATH" desc:"Relative path for OAuth upstream callback endpoint"`

	// TokenPath configures the relative path for the token endpoint.
	TokenPath string `json:"token_path" yaml:"token_path" flag:"oauth-token-path" env:"MCP_OAUTH_TOKEN_PATH" desc:"Relative path for OAuth token endpoint"`

	// AccessTokenTTLSeconds controls how long minted access tokens remain valid.
	AccessTokenTTLSeconds int `json:"access_token_ttl_seconds" yaml:"access_token_ttl_seconds" flag:"oauth-access-token-ttl-seconds" env:"MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS" desc:"Access token lifetime in seconds"`

	// RefreshTokenTTLSeconds controls how long minted refresh tokens remain valid.
	RefreshTokenTTLSeconds int `json:"refresh_token_ttl_seconds" yaml:"refresh_token_ttl_seconds" flag:"oauth-refresh-token-ttl-seconds" env:"MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS" desc:"Refresh token lifetime in seconds"`

	// SigningSecret is the server-side symmetric secret used to HKDF-derive
	// keys for every stateless OAuth JWE this server mints: pending-auth
	// state (the upstream `state` parameter) and the downstream auth-code
	// returned from /oauth/callback. Required whenever OAuth broker mode is
	// active (forward, or gating + broker_upstream). Per #115 v1 issues no
	// downstream refresh tokens and no DCR client_secrets.
	SigningSecret string `json:"signing_secret" yaml:"signing_secret" flag:"oauth-signing-secret" env:"MCP_OAUTH_SIGNING_SECRET" desc:"Server-side HKDF master secret for OAuth JWE artifacts (pending-auth state, downstream auth codes). Required whenever broker mode is active."`
}

// NormalizedMode returns the OAuth mode lowercased and trimmed; empty input
// defaults to "gating".
func (cfg OAuthConfig) NormalizedMode() string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "forward":
		return "forward"
	case "gating":
		return "gating"
	case "":
		return "gating"
	default:
		return mode
	}
}

// IsForwardMode reports whether the configured mode is "forward".
func (cfg OAuthConfig) IsForwardMode() bool {
	return cfg.NormalizedMode() == "forward"
}

// IsGatingMode reports whether the configured mode is "gating" (or unset).
func (cfg OAuthConfig) IsGatingMode() bool {
	return cfg.NormalizedMode() == "gating"
}
