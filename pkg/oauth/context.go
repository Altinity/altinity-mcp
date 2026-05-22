package oauth

import "context"

// contextKey avoids collisions with other packages using context.WithValue.
type contextKey string

// Context keys for OAuth bearer + validated claims. JWE keys stay in pkg/server.
const (
	TokenKey  contextKey = "oauth_token"
	ClaimsKey contextKey = "oauth_claims"
)

// TokenFromContext returns the raw bearer token previously stored on the
// request context by AuthInjector. Empty if not set.
func TokenFromContext(ctx context.Context) string {
	if v := ctx.Value(TokenKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ClaimsFromContext returns the validated claims previously stored on the
// request context by AuthInjector. Nil if not set.
func ClaimsFromContext(ctx context.Context) *Claims {
	if v := ctx.Value(ClaimsKey); v != nil {
		if c, ok := v.(*Claims); ok {
			return c
		}
	}
	return nil
}

// WithToken returns a copy of ctx carrying tok under TokenKey.
func WithToken(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, TokenKey, tok)
}

// WithClaims returns a copy of ctx carrying claims under ClaimsKey.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ClaimsKey, claims)
}
