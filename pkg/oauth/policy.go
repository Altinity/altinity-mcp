package oauth

import "strings"

// clockSkewSecs bounds the tolerance applied to exp/nbf/iat claims. Static
// rather than configurable so every Verifier and the ch-jwt-verify sidecar
// share the same window.
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
// and whitespace-insensitively. Used by the ch-jwt-verify sidecar for its
// allowed_email_domains / allowed_hosted_domains policies.
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
	scopeSet := make(map[string]bool, len(tokenScopes))
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
