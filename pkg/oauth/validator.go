package oauth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ExtractTokenFromRequest extracts an OAuth bearer token from an HTTP request,
// per MCP authorization spec §Token Requirements:
//
//	"MCP client MUST use the Authorization request header field defined in
//	 OAuth 2.1 §5.1.1: Authorization: Bearer <access-token>"
//	"Access tokens MUST NOT be included in the URI query string"
//
// Only the Authorization header is accepted.
func ExtractTokenFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// RequiresLocalValidation reports whether the auth layer should call
// ValidateToken on inbound bearers. We always do, in both gating and forward
// modes — ValidateToken itself decides what kind of validation applies for
// the configured mode and token shape.
func (v *Verifier) RequiresLocalValidation() bool {
	return v.cfg.Enabled
}

// ValidateToken validates an OAuth bearer and returns claims.
//
// Both modes route through the JWKS-based external-JWT validator: under
// gating, MCP is a pure resource server and the bearer is an upstream IdP
// (Auth0) access token; under forward, MCP proxies the upstream IdP token to
// the client unchanged. In both cases local validation is signature + iss +
// aud + exp against the configured JWKS.
//
// Two cases soft-pass (return nil claims, nil error) — the auth layer accepts
// the request and forwards to ClickHouse, which is then the sole validator:
//
//  1. Opaque (non-JWT) bearers — RFC 7662 introspection is not implemented;
//     local validation isn't possible.
//  2. JWT bearers with neither Issuer nor JWKSURL configured — operator
//     hasn't told us where to fetch verification keys.
//
// Soft-pass preserves compatibility with deployments that pre-date C-1 and
// rely entirely on ClickHouse-side validation. See docs/oauth_next_refactor.md
// for the plan to remove soft-pass once token introspection lands.
func (v *Verifier) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	if !v.cfg.Enabled {
		return nil, nil
	}

	if token == "" {
		return nil, ErrMissingToken
	}

	mode := v.cfg.NormalizedMode()
	if !looksLikeJWT(token) {
		if v.cfg.IsGatingMode() {
			log.Error().Str("mode", mode).Msg("OAuth token is not a JWT; gating mode requires a signed JWT from the upstream AS")
			return nil, ErrInvalidToken
		}
		log.Debug().Str("mode", mode).Msg("Bearer is opaque (not a JWT); skipping local validation, deferring to ClickHouse")
		return nil, nil
	}
	if strings.TrimSpace(v.cfg.JWKSURL) == "" && strings.TrimSpace(v.cfg.Issuer) == "" {
		log.Debug().Str("mode", mode).Msg("JWT received but neither oauth_issuer nor jwks_url is configured; skipping local validation")
		return nil, nil
	}
	claims, err := v.parseAndVerifyExternalJWT(ctx, token, v.cfg.Audience)
	if err != nil {
		log.Error().Err(err).Str("mode", mode).Msg("Failed to validate OAuth token")
		return nil, err
	}

	return v.validateClaims(claims)
}

// validateClaims applies post-signature-verification checks: audience (slash-
// normalised), exp/nbf/iat (with clockSkewSecs tolerance), required scopes,
// and identity policy (email_verified, allowed domains).
func (v *Verifier) validateClaims(claims *Claims) (*Claims, error) {
	// Issuer enforcement happens in parseAndVerifyExternalJWT, the only path
	// that reaches here. Re-validating here would duplicate the check.

	if v.cfg.Audience != "" {
		if len(claims.Audience) == 0 {
			log.Error().Str("expected", v.cfg.Audience).Msg("OAuth token missing audience claim")
			return nil, ErrInvalidToken
		}
		if !audienceMatchesResource(claims.Audience, v.cfg.Audience) {
			log.Error().Str("expected", v.cfg.Audience).Strs("got", claims.Audience).Msg("OAuth token audience mismatch")
			return nil, ErrInvalidToken
		}
	}

	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+clockSkewSecs {
		log.Error().Int64("exp", claims.ExpiresAt).Msg("OAuth token expired")
		return nil, ErrTokenExpired
	}
	if claims.NotBefore > 0 && now+clockSkewSecs < claims.NotBefore {
		log.Error().Int64("nbf", claims.NotBefore).Msg("OAuth token not yet valid")
		return nil, ErrInvalidToken
	}
	if claims.IssuedAt > 0 && claims.IssuedAt > now+clockSkewSecs {
		log.Error().Int64("iat", claims.IssuedAt).Msg("OAuth token issued in the future")
		return nil, ErrInvalidToken
	}

	if len(v.cfg.RequiredScopes) > 0 {
		if !HasRequiredScopes(claims.Scopes, v.cfg.RequiredScopes) {
			log.Error().Strs("required", v.cfg.RequiredScopes).Strs("got", claims.Scopes).Msg("OAuth token missing required scopes")
			return nil, ErrInsufficientScopes
		}
	}

	return claims, nil
}

// ValidateUpstreamIdentityToken parses an upstream identity token using the
// JWKS path (no soft-pass). Used by the broker's /oauth/callback after
// exchanging the upstream authorization code for an id_token: it verifies the
// redemption was legitimate (signature/iss/aud/exp) without imposing
// identity policy — domain allow-listing and verified-email enforcement now
// live in the CH-side ch-jwt-verify sidecar.
func (v *Verifier) ValidateUpstreamIdentityToken(ctx context.Context, token, expectedAudience string) (*Claims, error) {
	return v.parseAndVerifyExternalJWT(ctx, token, expectedAudience)
}
