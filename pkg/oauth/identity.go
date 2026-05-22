package oauth

import (
	"strings"

	"github.com/rs/zerolog/log"
)

// clockSkewSecs bounds the tolerance applied to exp/nbf/iat claims. Static
// rather than configurable; the next refactor (see docs/oauth_next_refactor.md
// § PR-1) lifts this into a per-Verifier option via go-sdk's
// RequireBearerTokenOptions.ClockSkew.
const clockSkewSecs = int64(60)

// EmailDomain returns the lowercased domain portion of an email address, or
// "" when the input is malformed. Trimmed first so leading/trailing whitespace
// doesn't smuggle past the @ split.
func EmailDomain(email string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// ContainsDomain reports whether target matches any domain in domains, case-
// and whitespace-insensitively. Used for the allowed_email_domains and
// allowed_hosted_domains identity policies.
func ContainsDomain(domains []string, target string) bool {
	for _, domain := range domains {
		if strings.EqualFold(strings.TrimSpace(domain), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

// HasRequiredScopes reports whether tokenScopes is a superset of
// requiredScopes. Comparison is exact (case- and whitespace-sensitive) since
// OAuth scope strings are user-defined and case-sensitive per RFC 6749 §3.3.
func HasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	scopeSet := make(map[string]bool)
	for _, s := range tokenScopes {
		scopeSet[s] = true
	}
	for _, required := range requiredScopes {
		if !scopeSet[required] {
			return false
		}
	}
	return true
}

// validateIdentityPolicy applies the configured email_verified, allowed_email_domains
// and allowed_hosted_domains checks. Returns ErrEmailNotVerified or
// ErrUnauthorizedDomain on failure.
func (v *Verifier) validateIdentityPolicy(claims *Claims) error {
	cfg := v.cfg
	if !cfg.AllowUnverifiedEmail && claims.Email != "" && !claims.EmailVerified {
		log.Error().Str("email", claims.Email).Msg("OAuth identity email is not verified")
		return ErrEmailNotVerified
	}

	if len(cfg.AllowedEmailDomains) > 0 {
		domain := EmailDomain(claims.Email)
		if domain == "" || !ContainsDomain(cfg.AllowedEmailDomains, domain) {
			log.Error().Str("email", claims.Email).Strs("allowed_domains", cfg.AllowedEmailDomains).Msg("OAuth identity email domain is not allowed")
			return ErrUnauthorizedDomain
		}
	}

	if len(cfg.AllowedHostedDomains) > 0 {
		if claims.HostedDomain == "" || !ContainsDomain(cfg.AllowedHostedDomains, claims.HostedDomain) {
			log.Error().Str("hosted_domain", claims.HostedDomain).Strs("allowed_hosted_domains", cfg.AllowedHostedDomains).Msg("OAuth identity hosted domain is not allowed")
			return ErrUnauthorizedDomain
		}
	}

	return nil
}

// ValidateIdentityPolicyClaims is the exported wrapper used by the broker to
// re-run the identity policy after exchanging an upstream identity token.
func (v *Verifier) ValidateIdentityPolicyClaims(claims *Claims) error {
	return v.validateIdentityPolicy(claims)
}
