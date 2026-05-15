package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/net/idna"
)

// CIMD = OAuth Client ID Metadata Document
// (draft-ietf-oauth-client-id-metadata-document). Replaces DCR for inbound MCP
// OAuth clients per Altinity/altinity-mcp#115.
//
// The MCP client publishes a JSON metadata document at an HTTPS URL and uses
// that URL as its `client_id`. altinity-mcp fetches the document at /authorize
// (and /token), validates it, and uses the contents as the registered client
// for that OAuth flow. No registration endpoint, no per-(client × server) JWE.

const (
	cimdMaxURLLength         = 2048
	cimdMaxBodyBytes         = 5 * 1024
	cimdMaxRedirectURIs      = 20
	cimdMaxRedirectURILength = 2048
	cimdMaxClientNameLength  = 128
	cimdFetchTimeout         = 3 * time.Second
	cimdCacheCap             = 1024
	cimdDefaultCacheTTL      = 5 * time.Minute
	cimdMaxCacheTTL          = 1 * time.Hour
	cimdNegativeCacheTTL     = 30 * time.Second
)

var (
	errCIMDInvalidURL      = errors.New("cimd: invalid client_id URL")
	errCIMDSSRFBlocked     = errors.New("cimd: target address blocked by SSRF policy")
	errCIMDFetch           = errors.New("cimd: metadata fetch failed")
	errCIMDInvalidMetadata = errors.New("cimd: invalid metadata document")
)

// validateCIMDClientIDURL parses and validates a CIMD client_id URL against the
// strict rules from issue #115 § "CIMD client identifier URL validation".
// Returns the parsed URL on success; on failure the error wraps errCIMDInvalidURL.
func validateCIMDClientIDURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > cimdMaxURLLength {
		return nil, fmt.Errorf("%w: length out of range", errCIMDInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", errCIMDInvalidURL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme must be https", errCIMDInvalidURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: userinfo not allowed", errCIMDInvalidURL)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("%w: fragment not allowed", errCIMDInvalidURL)
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("%w: query not allowed", errCIMDInvalidURL)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: hostname required", errCIMDInvalidURL)
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, fmt.Errorf("%w: port %s not allowed (must be 443)", errCIMDInvalidURL, port)
	}
	asciiHost, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return nil, fmt.Errorf("%w: hostname IDNA failure: %v", errCIMDInvalidURL, err)
	}
	if asciiHost != host {
		return nil, fmt.Errorf("%w: hostname must be lowercase ASCII (got %q, normalized %q)", errCIMDInvalidURL, host, asciiHost)
	}
	if u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("%w: non-empty path required", errCIMDInvalidURL)
	}
	if err := validateCIMDPath(u.EscapedPath()); err != nil {
		return nil, err
	}
	return u, nil
}

// validateCIMDPath rejects dot-segments (raw or percent-encoded), encoded
// slashes, and encoded backslashes. The dot-segment test uses the issue #115
// formulation: "Reject paths where applying standard dot-segment removal
// would change the path." `path.Clean` does exactly that. Encoded slashes and
// backslashes are checked separately because path.Clean can't see them — they
// would change segment boundaries after decoding, which is the attack we're
// blocking.
func validateCIMDPath(rawPath string) error {
	if !strings.HasPrefix(rawPath, "/") {
		return fmt.Errorf("%w: path must start with /", errCIMDInvalidURL)
	}
	upper := strings.ToUpper(rawPath)
	if strings.Contains(upper, "%2F") || strings.Contains(upper, "%5C") {
		return fmt.Errorf("%w: encoded slash or backslash in path", errCIMDInvalidURL)
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		return fmt.Errorf("%w: invalid percent-encoding in path", errCIMDInvalidURL)
	}
	// path.Clean strips trailing slashes ("/a/" → "/a"), but RFC 3986
	// treats a trailing slash as a significant, legal path. Accept the path
	// if it differs from its Clean form only by a single trailing slash.
	cleaned := path.Clean(decoded)
	if cleaned != decoded && cleaned+"/" != decoded {
		return fmt.Errorf("%w: dot-segment in path", errCIMDInvalidURL)
	}
	return nil
}

// ssrfBlockedCIDRs is the single audit-friendly list of address ranges we
// refuse to dial during CIMD metadata fetch. Tracks the IANA special-purpose
// address registry (RFC 6890 + IPv6 registry RFC 8190). Comments give the
// RFC and human name for each entry so future audits can read it
// linearly.
var ssrfBlockedCIDRs = mustParseCIDRs(
	// IPv4 — IANA IPv4 Special-Purpose Address Registry
	"0.0.0.0/8",       // RFC 1122 — "this network"
	"10.0.0.0/8",      // RFC 1918 — private
	"100.64.0.0/10",   // RFC 6598 — Carrier-Grade NAT
	"127.0.0.0/8",     // RFC 1122 — loopback
	"169.254.0.0/16",  // RFC 3927 — link-local
	"172.16.0.0/12",   // RFC 1918 — private
	"192.0.0.0/24",    // RFC 6890 — IETF protocol assignments
	"192.0.2.0/24",    // RFC 5737 — TEST-NET-1 (documentation)
	"192.168.0.0/16",  // RFC 1918 — private
	"198.18.0.0/15",   // RFC 2544 — benchmarking
	"198.51.100.0/24", // RFC 5737 — TEST-NET-2 (documentation)
	"203.0.113.0/24",  // RFC 5737 — TEST-NET-3 (documentation)
	"224.0.0.0/4",     // RFC 5771 — multicast
	"240.0.0.0/4",     // RFC 1112 — reserved (includes 255.255.255.255 broadcast)
	// IPv6 — IANA IPv6 Special-Purpose Address Registry
	"::1/128",       // RFC 4291 — loopback
	"64:ff9b::/96",  // RFC 6052 — IPv4/IPv6 translation
	"100::/64",      // RFC 6666 — discard prefix
	"2001:db8::/32", // RFC 3849 — documentation
	"fc00::/7",      // RFC 4193 — unique local
	"fe80::/10",     // RFC 4291 — link-local
	"ff00::/8",      // RFC 4291 — multicast
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("cimd: bad SSRF CIDR %q: %v", c, err))
		}
		out = append(out, n)
	}
	return out
}

// isBlockedIP reports whether ip falls in a special-use range we must refuse
// to dial during CIMD metadata fetch.
func isBlockedIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return true
	}
	for _, n := range ssrfBlockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// cimdResolver carries the dependencies needed to resolve, fetch, and cache a
// CIMD client metadata document. Tests build their own resolver pointed at a
// custom resolverFunc + http.Client so they can simulate SSRF, redirects, body
// limits, and cache TTL without a real network.
type cimdResolver struct {
	httpClient *http.Client
	resolveIP  func(ctx context.Context, host string) ([]net.IP, error)
	cache      *cimdCache
	now        func() time.Time
}

// newCIMDResolver constructs a resolver with an SSRF-safe http.Client. If
// resolveIP is nil it uses net.DefaultResolver.
func newCIMDResolver(resolveIP func(ctx context.Context, host string) ([]net.IP, error)) *cimdResolver {
	if resolveIP == nil {
		resolveIP = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	r := &cimdResolver{
		resolveIP: resolveIP,
		cache:     newCIMDCache(cimdCacheCap),
		now:       time.Now,
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           r.ssrfSafeDial,
		TLSHandshakeTimeout:   cimdFetchTimeout,
		ResponseHeaderTimeout: cimdFetchTimeout,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	r.httpClient = &http.Client{
		Transport: tr,
		Timeout:   cimdFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return r
}

// ssrfSafeDial resolves the host explicitly, pins the dial to a validated IP,
// and re-checks the connected remote address before returning.
//
// Why the post-dial check is essentially belt-and-suspenders here: we dial
// JoinHostPort(pinned.String(), port) — an explicit IP literal — so the
// resolver cannot rebind to a different address. The re-check survives only
// as defense against future refactors that swap the dial target back to the
// hostname (e.g. for SNI symmetry). Cheap; keep it.
func (r *cimdResolver) ssrfSafeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := r.resolveIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: dns: %v", errCIMDSSRFBlocked, err)
	}
	var pinned net.IP
	for _, ip := range ips {
		if !isBlockedIP(ip) {
			pinned = ip
			break
		}
	}
	if pinned == nil {
		return nil, fmt.Errorf("%w: no public address for host %s", errCIMDSSRFBlocked, host)
	}
	var d net.Dialer
	d.Timeout = cimdFetchTimeout
	conn, err := d.DialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
	if err != nil {
		return nil, err
	}
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if isBlockedIP(tcpAddr.IP) {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: post-dial address is blocked", errCIMDSSRFBlocked)
		}
	}
	return conn, nil
}

// resolveCIMDClient is the entry point used by handlers. It delegates to the
// resolver owned by the application; tests construct the application with a
// resolver pointed at an in-process httptest.Server (see cimd_test.go).
func (a *application) resolveCIMDClient(ctx context.Context, clientIDURL string) (*statelessRegisteredClient, error) {
	return a.cimdResolver.resolve(ctx, clientIDURL)
}

func (r *cimdResolver) resolve(ctx context.Context, clientIDURL string) (*statelessRegisteredClient, error) {
	if _, err := validateCIMDClientIDURL(clientIDURL); err != nil {
		r.cache.put(clientIDURL, &cimdCacheEntry{err: err, expiresAt: r.now().Add(cimdNegativeCacheTTL)}, r.now())
		return nil, err
	}
	if e, ok := r.cache.get(clientIDURL, r.now()); ok {
		if e.err != nil {
			return nil, e.err
		}
		return e.client, nil
	}
	client, ttl, err := r.fetchAndValidate(ctx, clientIDURL)
	now := r.now()
	if err != nil {
		// Negative-cache only stably-wrong outcomes (abuse control per #115
		// § Caching). Transient fetch failures — upstream 5xx, timeouts,
		// client disconnects that propagate as context.Canceled — must NOT
		// poison the cache: a single bad fetch from one user would lock all
		// users of that client_id URL out for cimdNegativeCacheTTL.
		switch {
		case errors.Is(err, errCIMDInvalidMetadata),
			errors.Is(err, errCIMDInvalidURL),
			errors.Is(err, errCIMDSSRFBlocked):
			r.cache.put(clientIDURL, &cimdCacheEntry{err: err, expiresAt: now.Add(cimdNegativeCacheTTL)}, now)
		}
		return nil, err
	}
	if ttl > 0 {
		r.cache.put(clientIDURL, &cimdCacheEntry{client: client, expiresAt: now.Add(ttl)}, now)
	}
	return client, nil
}

func (r *cimdResolver) fetchAndValidate(ctx context.Context, clientIDURL string) (*statelessRegisteredClient, time.Duration, error) {
	// Detach the fetch from the inbound request's cancellation. The fetch is
	// shared across goroutines via the cache, so an inbound disconnect must
	// not abort it (and produce a context.Canceled error that other waiters
	// observe). The dedicated cimdFetchTimeout still bounds the call.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cimdFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientIDURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: build request: %v", errCIMDFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", errCIMDFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 3 {
		return nil, 0, fmt.Errorf("%w: unexpected redirect %d", errCIMDFetch, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: HTTP %d", errCIMDFetch, resp.StatusCode)
	}
	if !isApplicationJSON(resp.Header.Get("Content-Type")) {
		return nil, 0, fmt.Errorf("%w: content-type %q not application/json", errCIMDFetch, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(cimdMaxBodyBytes+1)))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: body read: %v", errCIMDFetch, err)
	}
	if len(body) > cimdMaxBodyBytes {
		return nil, 0, fmt.Errorf("%w: body exceeds %d bytes", errCIMDFetch, cimdMaxBodyBytes)
	}
	client, err := parseCIMDMetadata(clientIDURL, body)
	if err != nil {
		return nil, 0, err
	}
	return client, cacheTTLFromHeader(resp.Header.Get("Cache-Control")), nil
}

// cacheTTLFromHeader maps the response's Cache-Control header to a positive
// cache TTL or zero (do-not-cache). Returns cimdDefaultCacheTTL when the
// header is absent or carries no relevant directives, capped at
// cimdMaxCacheTTL.
//
// Semantics per RFC 7234 §5.2:
//   - no-store / no-cache  → ttl = 0 (do not reuse from cache)
//   - max-age=0 or negative → ttl = 0 (RFC 7234 treats negative as 0)
//   - max-age=N            → ttl = min(N, cap)
//   - none of the above    → ttl = default
//
// Directive matching is exact: a stray substring like "x-no-storage" does
// NOT trigger no-store.
// isApplicationJSON matches RFC 7231 §3.1.1.5 media-type syntax: the bare
// type is "application/json", optionally followed by ";" parameters
// (charset, boundary, etc.). A bare prefix match would falsely accept
// "application/json-ld", "application/jsonpatch+json", and similar
// distinct media types whose bodies don't shape-match CIMD documents.
func isApplicationJSON(ct string) bool {
	mt, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mt), "application/json")
}

func cacheTTLFromHeader(cc string) time.Duration {
	if cc == "" {
		return cimdDefaultCacheTTL
	}
	maxAge := time.Duration(-1) // sentinel: directive absent
	for _, raw := range strings.Split(cc, ",") {
		directive := strings.TrimSpace(strings.ToLower(raw))
		if directive == "" {
			continue
		}
		switch {
		case directive == "no-store" || directive == "no-cache":
			return 0
		case strings.HasPrefix(directive, "max-age="):
			n, err := strconv.Atoi(strings.TrimPrefix(directive, "max-age="))
			if err != nil {
				continue // malformed value; ignore directive
			}
			if n <= 0 {
				return 0 // RFC 7234: max-age=0 (or negative) means uncached.
			}
			// Clamp n before the *time.Second multiply so we don't overflow
			// int64 nanoseconds for absurd max-age values (n*1e9 overflows
			// when n > ~9.22e9). Without this, a CIMD doc with
			// "Cache-Control: max-age=9999999999" would wrap to negative
			// and silently fall back to cimdDefaultCacheTTL.
			const maxSeconds = int(cimdMaxCacheTTL / time.Second)
			if n > maxSeconds {
				return cimdMaxCacheTTL
			}
			maxAge = time.Duration(n) * time.Second
		}
	}
	if maxAge < 0 {
		return cimdDefaultCacheTTL
	}
	if maxAge > cimdMaxCacheTTL {
		return cimdMaxCacheTTL
	}
	return maxAge
}

// parseCIMDMetadata decodes the document and applies the schema rules from
// issue #115 §"Metadata schema validation". Treats the body as untrusted.
//
// The wire shape of a CIMD document matches RFC 7591 §3.2.1 client registration
// response — same field names, types, and JSON tags — so we reuse the SDK's
// `oauthex.ClientRegistrationResponse` rather than maintaining a parallel
// struct. Extra fields the SDK knows about (logo_uri, tos_uri, jwks, etc.) are
// safely ignored because we don't read them.
func parseCIMDMetadata(clientIDURL string, body []byte) (*statelessRegisteredClient, error) {
	// json.Unmarshal here rather than json.Decoder: oauthex.ClientRegistrationResponse
	// has a custom UnmarshalJSON that bypasses outer-decoder settings (UseNumber
	// would be a no-op), and we don't need trailing-token detection — a
	// well-formed CIMD doc is a single JSON object. The body was already
	// bounded by io.LimitReader at fetch time.
	var doc oauthex.ClientRegistrationResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", errCIMDInvalidMetadata, err)
	}
	if doc.ClientID != clientIDURL {
		return nil, fmt.Errorf("%w: client_id mismatch", errCIMDInvalidMetadata)
	}
	if doc.ClientName == "" || len(doc.ClientName) > cimdMaxClientNameLength {
		return nil, fmt.Errorf("%w: client_name length out of range", errCIMDInvalidMetadata)
	}
	if doc.ClientSecret != "" || !doc.ClientSecretExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: client_secret not allowed for CIMD public client", errCIMDInvalidMetadata)
	}
	if doc.TokenEndpointAuthMethod != "none" {
		return nil, fmt.Errorf("%w: token_endpoint_auth_method must be \"none\" (got %q)", errCIMDInvalidMetadata, doc.TokenEndpointAuthMethod)
	}
	if len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > cimdMaxRedirectURIs {
		return nil, fmt.Errorf("%w: redirect_uris count out of range", errCIMDInvalidMetadata)
	}
	seen := make(map[string]struct{}, len(doc.RedirectURIs))
	for _, ru := range doc.RedirectURIs {
		if ru == "" || len(ru) > cimdMaxRedirectURILength {
			return nil, fmt.Errorf("%w: redirect_uri length out of range", errCIMDInvalidMetadata)
		}
		if _, dup := seen[ru]; dup {
			return nil, fmt.Errorf("%w: duplicate redirect_uri", errCIMDInvalidMetadata)
		}
		seen[ru] = struct{}{}
		if err := validateCIMDRedirectURI(ru); err != nil {
			return nil, err
		}
	}
	if len(doc.GrantTypes) > 0 {
		hasAuthCode := false
		for _, gt := range doc.GrantTypes {
			switch gt {
			case "authorization_code":
				hasAuthCode = true
			case "refresh_token":
				// Tolerated in metadata, deliberately NOT honored in v1: a client
				// publishing ["authorization_code","refresh_token"] (which
				// claude.ai does today) silently gets no refresh capability —
				// .well-known/oauth-authorization-server only advertises
				// authorization_code and /token returns unsupported_grant_type
				// for refresh. If/when refresh ships, do NOT treat the CIMD
				// grant_types array as authoritative for what we issue — the AS
				// metadata is the source of truth.
			default:
				return nil, fmt.Errorf("%w: unsupported grant_type %q", errCIMDInvalidMetadata, gt)
			}
		}
		if !hasAuthCode {
			return nil, fmt.Errorf("%w: grant_types must include authorization_code", errCIMDInvalidMetadata)
		}
	}
	if len(doc.ResponseTypes) > 0 {
		hasCode := false
		for _, rt := range doc.ResponseTypes {
			if rt == "code" {
				hasCode = true
			} else {
				return nil, fmt.Errorf("%w: unsupported response_type %q", errCIMDInvalidMetadata, rt)
			}
		}
		if !hasCode {
			return nil, fmt.Errorf("%w: response_types must include code", errCIMDInvalidMetadata)
		}
	}
	return &statelessRegisteredClient{RedirectURIs: doc.RedirectURIs}, nil
}

// validateCIMDRedirectURI: v1 requires https for all redirect URIs. Loopback
// http is intentionally NOT allowed because we ship no consent UI and no
// trusted-loopback-host allowlist; both known CIMD clients (claude.ai,
// ChatGPT) publish https redirect URIs.
func validateCIMDRedirectURI(ru string) error {
	u, err := url.Parse(ru)
	if err != nil {
		return fmt.Errorf("%w: redirect_uri parse: %v", errCIMDInvalidMetadata, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: redirect_uri scheme must be https (got %q)", errCIMDInvalidMetadata, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: redirect_uri host required", errCIMDInvalidMetadata)
	}
	return nil
}

// --- cache ---------------------------------------------------------------

type cimdCacheEntry struct {
	client    *statelessRegisteredClient
	err       error
	expiresAt time.Time
}

// cimdCache is a bounded FIFO with TTL. Eviction order is insertion order:
// on overflow we drop the oldest-inserted entry. `get` does NOT promote, so
// this is FIFO, not LRU. The distinction doesn't matter at our scale (cap
// ≫ unique CIMD URLs in practice) and FIFO has a simpler invariant.
type cimdCache struct {
	mu       sync.Mutex
	entries  map[string]*cimdCacheEntry
	order    []string
	capacity int
}

func newCIMDCache(capacity int) *cimdCache {
	if capacity <= 0 {
		capacity = 1
	}
	return &cimdCache{entries: make(map[string]*cimdCacheEntry, capacity), capacity: capacity}
}

func (c *cimdCache) get(key string, now time.Time) (*cimdCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if now.After(e.expiresAt) {
		c.evictLocked(key)
		return nil, false
	}
	return e, true
}

// put inserts/updates a cache entry. Negative entries do NOT override an
// existing unexpired positive entry (per issue #115 cache requirements). The
// now argument is the cache's logical clock — the caller passes the same
// value it uses for cache.get expiry, so put/get stay coherent under tests
// that fix time.
func (c *cimdCache) put(key string, e *cimdCacheEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.err != nil {
		if existing, ok := c.entries[key]; ok && existing.err == nil && existing.expiresAt.After(now) {
			return
		}
	}
	if _, exists := c.entries[key]; !exists {
		if len(c.entries) >= c.capacity {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = e
}

func (c *cimdCache) evictLocked(key string) {
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}
