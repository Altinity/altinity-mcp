package oauth

import (
	"encoding/json"
	"strings"
)

// BuildClickHouseHeaders builds the HTTP headers that forward-mode requires
// when proxying a request to ClickHouse: the bearer itself (under
// `Authorization` or a custom name) plus any claims-to-headers mapping. The
// caller is responsible for not invoking this in gating mode — that case
// returns nil per the legacy contract.
func BuildClickHouseHeaders(cfg OAuthConfig, token string, claims *Claims) map[string]string {
	if !cfg.IsForwardMode() {
		return nil
	}

	headers := make(map[string]string)

	headerName := cfg.ClickHouseHeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	if headerName == "Authorization" {
		headers[headerName] = "Bearer " + token
	} else {
		headers[headerName] = token
	}

	if len(cfg.ClaimsToHeaders) > 0 && claims != nil {
		for claimName, hdr := range cfg.ClaimsToHeaders {
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
				if v, ok := claims.Extra[claimName]; ok {
					if strVal, ok := v.(string); ok {
						value = strVal
					} else if jsonBytes, err := json.Marshal(v); err == nil {
						value = string(jsonBytes)
					}
				}
			}
			if value != "" {
				headers[hdr] = value
			}
		}
	}

	return headers
}

// EmailFromNamespacedExtra returns the first string-valued claim whose key
// ends with `/email` from the JWT's non-standard claim map. Auth0 third-party
// (DCR) tokens in enhanced security mode silently drop non-namespaced custom
// claims, forcing operators to set email under a URL-prefixed key (e.g.
// `https://mcp.altinity.cloud/email`). Looking up by suffix lets MCP accept
// any namespace the operator chose.
func EmailFromNamespacedExtra(extra map[string]interface{}) string {
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
