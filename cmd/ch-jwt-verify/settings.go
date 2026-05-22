package main

// settingsFromScopes builds the ClickHouse session-settings map the sidecar
// returns to ClickHouse. The CH http_authentication response parser
// (src/Access/SettingsAuthResponseParser.cpp) treats the JSON `settings` field
// as session settings applied for the duration of the authenticating query
// only, so the sidecar can hand back per-scope restrictions (readonly,
// max_memory_usage, etc.) without persisting any state in CH.
//
// Scopes that the operator hasn't mapped are silently ignored — a token with
// an unknown scope but a known one still gets the known one's settings.
// Conflicts between scopes (same setting, different values) are resolved by
// the order they appear in tokenScopes; first writer wins.
func settingsFromScopes(tokenScopes []string, mapping map[string]map[string]string) map[string]string {
	if len(mapping) == 0 || len(tokenScopes) == 0 {
		return nil
	}
	out := make(map[string]string)
	for _, scope := range tokenScopes {
		s, ok := mapping[scope]
		if !ok {
			continue
		}
		for k, v := range s {
			if _, exists := out[k]; exists {
				continue
			}
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
