package oauth

import (
	"encoding/json"
	"strings"
)

// Claims represents the validated claims from an OAuth token. Standard OIDC
// claims are first-class fields; everything else is captured in Extra so the
// broker can read fields like upstream-namespaced email or refresh-window
// metadata without losing information.
type Claims struct {
	Subject       string                 `json:"sub"`
	Issuer        string                 `json:"iss"`
	Audience      []string               `json:"aud"`
	ExpiresAt     int64                  `json:"exp"`
	IssuedAt      int64                  `json:"iat"`
	NotBefore     int64                  `json:"nbf,omitempty"`
	Scopes        []string               `json:"scope"`
	Email         string                 `json:"email,omitempty"`
	Name          string                 `json:"name,omitempty"`
	HostedDomain  string                 `json:"hd,omitempty"`
	EmailVerified bool                   `json:"email_verified,omitempty"`
	Extra         map[string]interface{} `json:"-"`
}

// claimsFromRawClaims projects raw JWT claims into Claims. Standard claims are
// populated by name (handling both float64 and json.Number representations);
// non-standard claims land in Extra unchanged. Audience and scope each accept
// the two RFC-defined representations (string or array).
func claimsFromRawClaims(rawClaims map[string]interface{}) *Claims {
	claims := &Claims{
		Extra: make(map[string]interface{}),
	}

	if sub, ok := rawClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if iss, ok := rawClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if exp, ok := rawClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}
	if exp, ok := rawClaims["exp"].(json.Number); ok {
		if n, err := exp.Int64(); err == nil {
			claims.ExpiresAt = n
		}
	}
	if iat, ok := rawClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if iat, ok := rawClaims["iat"].(json.Number); ok {
		if n, err := iat.Int64(); err == nil {
			claims.IssuedAt = n
		}
	}
	if nbf, ok := rawClaims["nbf"].(float64); ok {
		claims.NotBefore = int64(nbf)
	}
	if nbf, ok := rawClaims["nbf"].(json.Number); ok {
		if n, err := nbf.Int64(); err == nil {
			claims.NotBefore = n
		}
	}
	if email, ok := rawClaims["email"].(string); ok {
		claims.Email = email
	}
	if name, ok := rawClaims["name"].(string); ok {
		claims.Name = name
	}
	if hd, ok := rawClaims["hd"].(string); ok {
		claims.HostedDomain = hd
	}
	if emailVerified, ok := rawClaims["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}
	if emailVerified, ok := rawClaims["email_verified"].(string); ok {
		claims.EmailVerified = strings.EqualFold(emailVerified, "true")
	}

	switch aud := rawClaims["aud"].(type) {
	case string:
		claims.Audience = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, audStr)
			}
		}
	}

	switch scope := rawClaims["scope"].(type) {
	case string:
		claims.Scopes = strings.Fields(scope)
	case []interface{}:
		for _, s := range scope {
			if scopeStr, ok := s.(string); ok {
				claims.Scopes = append(claims.Scopes, scopeStr)
			}
		}
	}

	standardClaims := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
		"scope": true, "email": true, "name": true, "hd": true, "email_verified": true,
	}
	for k, v := range rawClaims {
		if !standardClaims[k] {
			claims.Extra[k] = v
		}
	}

	return claims
}
