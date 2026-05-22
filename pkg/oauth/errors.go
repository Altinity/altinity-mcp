package oauth

import "errors"

var (
	// ErrMissingToken is returned when an OAuth bearer token is missing from the request.
	ErrMissingToken = errors.New("missing OAuth token")
	// ErrInvalidToken is returned when an OAuth bearer token fails validation.
	ErrInvalidToken = errors.New("invalid OAuth token")
	// ErrTokenExpired is returned when an OAuth token has expired (with clock-skew tolerance).
	ErrTokenExpired = errors.New("OAuth token expired")
	// ErrInsufficientScopes is returned when a token doesn't carry the required scopes.
	ErrInsufficientScopes = errors.New("insufficient OAuth scopes")
	// ErrEmailNotVerified is returned by the ch-jwt-verify sidecar when a
	// token's email claim is unverified and the sidecar's identity policy
	// does not allow unverified emails.
	ErrEmailNotVerified = errors.New("OAuth email is not verified")
	// ErrUnauthorizedDomain is returned by the ch-jwt-verify sidecar when a
	// token's principal domain is not in the configured allowed-email-domain
	// / allowed-hosted-domain list.
	ErrUnauthorizedDomain = errors.New("OAuth identity domain is not allowed")
	// ErrTransient marks a validation failure that callers should NOT treat
	// as a permanent rejection: network errors fetching JWKS / OIDC
	// discovery, upstream 5xx, and the "no JWK found for kid" race where
	// the IdP's CDN hasn't propagated a freshly-rotated key yet. The
	// ch-jwt-verify sidecar uses errors.Is(err, ErrTransient) to skip the
	// negative cache so a one-off blip on one replica doesn't strand a
	// legitimate token for negative_ttl while peers serve it fine.
	ErrTransient = errors.New("transient OAuth validation failure")
)
