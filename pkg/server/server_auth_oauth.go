package server

import (
	"context"
	"net/http"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
)

// Re-exports of pkg/oauth identifiers so existing pkg/server-aware callers and
// tests continue to compile after the extraction. Prefer the oauth package
// directly in new code.

// OAuthClaims is the validated claim set from an OAuth token. Type alias so
// pkg/server callers and pkg/oauth callers share the same underlying type.
type OAuthClaims = oauth.Claims

// OpenIDConfiguration is the minimal subset of OIDC discovery metadata the
// broker reads. Returned by FetchOpenIDConfiguration as a thin composition of
// the SDK's oauthex.AuthServerMeta + Verifier.ResolveUserInfoEndpoint.
type OpenIDConfiguration struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	UserInfoEndpoint      string
}

// Error sentinels mirrored from pkg/oauth. errors.Is across the alias works
// because errors.Is unwraps to the same underlying error value.
var (
	ErrMissingOAuthToken       = oauth.ErrMissingToken
	ErrInvalidOAuthToken       = oauth.ErrInvalidToken
	ErrOAuthTokenExpired       = oauth.ErrTokenExpired
	ErrOAuthInsufficientScopes = oauth.ErrInsufficientScopes
)

// OAuthTokenKey / OAuthClaimsKey re-export the pkg/oauth context keys so
// values stored under one are readable via the other. Declared as vars (not
// const) because contextKey is a value-type from pkg/oauth's perspective.
var (
	OAuthTokenKey  any = oauth.TokenKey
	OAuthClaimsKey any = oauth.ClaimsKey
)

// ExtractOAuthTokenFromRequest reads the Authorization: Bearer header.
func (s *ClickHouseJWEServer) ExtractOAuthTokenFromRequest(r *http.Request) string {
	return oauth.ExtractTokenFromRequest(r)
}

// ExtractOAuthTokenFromCtx returns the OAuth token stored on ctx by the auth
// injector, or "" if none.
func (s *ClickHouseJWEServer) ExtractOAuthTokenFromCtx(ctx context.Context) string {
	return oauth.TokenFromContext(ctx)
}

// oauthRequiresLocalValidation reports whether the auth layer should call
// ValidateOAuthToken on inbound bearers. Delegates to the Verifier.
func (s *ClickHouseJWEServer) oauthRequiresLocalValidation() bool {
	return s.verifier().RequiresLocalValidation()
}

// ValidateOAuthToken validates an OAuth bearer and returns claims. See
// pkg/oauth.Verifier.ValidateToken for the full contract (including the two
// soft-pass cases).
func (s *ClickHouseJWEServer) ValidateOAuthToken(token string) (*OAuthClaims, error) {
	return s.verifier().ValidateToken(context.Background(), token)
}

// ValidateUpstreamIdentityToken parses an upstream identity token (no
// soft-pass) and applies signature/iss/aud/exp checks. Used by the broker on
// /callback to verify the redemption was legitimate. Identity-policy
// enforcement (verified-email, domain allow-listing) is now handled by the
// CH-side ch-jwt-verify sidecar.
func (s *ClickHouseJWEServer) ValidateUpstreamIdentityToken(token, expectedAudience string) (*OAuthClaims, error) {
	return s.verifier().ValidateUpstreamIdentityToken(context.Background(), token, expectedAudience)
}

// FetchOpenIDConfiguration returns the discovered OIDC metadata subset the
// broker needs. Composes go-sdk's auth-server-metadata discovery with our
// surgical userinfo_endpoint fallback (oauthex.AuthServerMeta is RFC 8414
// only and does not include userinfo_endpoint).
func (s *ClickHouseJWEServer) FetchOpenIDConfiguration(issuer string) (*OpenIDConfiguration, error) {
	ctx := context.Background()
	v := s.verifier()
	asMeta, err := v.FetchAuthServerMeta(ctx, issuer)
	if err != nil {
		return nil, err
	}
	userInfo, _ := v.ResolveUserInfoEndpoint(ctx, issuer)
	return &OpenIDConfiguration{
		Issuer:                asMeta.Issuer,
		AuthorizationEndpoint: asMeta.AuthorizationEndpoint,
		TokenEndpoint:         asMeta.TokenEndpoint,
		JWKSURI:               asMeta.JWKSURI,
		UserInfoEndpoint:      userInfo,
	}, nil
}

// verifier returns the lazily-initialised Verifier. The single
// NewClickHouseMCPServer construction path initialises s.oauthVerifier
// up-front, but tests construct ClickHouseJWEServer directly via struct
// literal, so this getter falls back to building one on demand.
func (s *ClickHouseJWEServer) verifier() *oauth.Verifier {
	if s.oauthVerifier == nil {
		s.oauthVerifier = oauth.NewVerifier(s.Config.Server.OAuth)
	}
	return s.oauthVerifier
}
