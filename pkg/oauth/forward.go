package oauth

import "strings"

// BuildClickHouseHeaders returns the headers MCP forwards to ClickHouse under
// forward mode: just the bearer wrapped as `Authorization: Bearer <token>`.
// Gating mode does not flow through this helper — its CH credentials are
// conveyed via the Basic header assembled by clickhouse-go from
// Auth.Username/Auth.Password.
func BuildClickHouseHeaders(cfg OAuthConfig, token string) map[string]string {
	if !cfg.IsForwardMode() {
		return nil
	}
	return map[string]string{
		"Authorization": "Bearer " + token,
	}
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
