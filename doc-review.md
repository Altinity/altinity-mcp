What's wrong or outdated

  1. mode: "terminate" is mentioned but deprecated. Line 164 says terminate but the code normalizes it to broker. The doc should use broker consistently and mention terminate only as a deprecated alias.
  2. broker mode description is wrong in the table. Line 268: broker issues limited self-signed MCP tokens — this is correct, but forward is described as "verifies external tokens" which it doesn't (it accepts
  by presence only in the MCP path).
  3. refresh_token_ttl_seconds described as "Reserved" (line 289). We just implemented refresh tokens — this is now active in broker mode.
  4. No mention of refresh tokens anywhere. The whole grant_type=refresh_token flow we just added is undocumented.
  5. broker_secret_key described as optional (line 178: empty default). We just made it required whenever OAuth is enabled. The doc should reflect this.
  6. Identity policy options missing. allowed_email_domains, allowed_hosted_domains, require_email_verified exist in the config but aren't documented in the reference table or YAML examples.
  7. userinfo_url not documented. It's a config option used for upstream userinfo lookups but missing from the reference.
  8. Example config at line 148 sets forward_to_clickhouse: false in a forward-mode example. This is the exact misconfiguration we added a startup warning for. Confusing as a recommended example.
  9. claims_to_headers note is misleading. Line 258 says it's "useful only when broker-mode validation is active" — but in forward mode with ClickHouse token_processors, you typically don't need
  claims_to_headers at all since ClickHouse validates the token itself.
  10. No "quick start" for the two main use cases. The doc jumps into details before explaining: "If you just want X, do this." The two main use cases are (a) forward mode with ClickHouse token_processors and
  (b) broker mode for MCP-only gating. Each needs a 5-line config example at the top.
  11. MCP Client Integration section (line 671) is vague. Doesn't mention that MCP clients discover OAuth via /.well-known/oauth-protected-resource → /.well-known/oauth-authorization-server → dynamic
  registration → PKCE auth code flow. This is the MCP spec's standard discovery mechanism.
  12. Line 681 about opaque tokens is buried in a paragraph and should be in the requirements or limitations section.

  What to add

  - Quick start section with minimal forward-mode and broker-mode examples (3-5 lines each)
  - Refresh token documentation — how it works, TTL, stateless limitations, broker-only
  - Identity policy section — allowed_email_domains, allowed_hosted_domains, require_email_verified
  - Security considerations — stateless refresh tokens (no revocation), forward mode doesn't validate tokens locally, broker_secret_key protects all stateless artifacts

  What to remove

  - The "MCP-only OAuth gating" section (lines 13-19) is confusingly named and duplicates broker mode
  - Redundant config examples — the "Full OAuth Configuration Reference" and the "Browser-Based MCP Login" minimal config are 80% identical
