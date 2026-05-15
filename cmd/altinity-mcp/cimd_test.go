package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- URL validation -----------------------------------------------------

func TestValidateCIMDClientIDURL_OK(t *testing.T) {
	cases := []string{
		"https://claude.ai/oauth/mcp-oauth-client-metadata",
		"https://chatgpt.com/.well-known/oauth-client-id",
		"https://example.com:443/x.json",
		"https://example.com/a/b/c.json",
	}
	for _, c := range cases {
		if _, err := validateCIMDClientIDURL(c); err != nil {
			t.Errorf("expected %q to validate, got %v", c, err)
		}
	}
}

func TestValidateCIMDClientIDURL_Reject(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"http_scheme":       "http://example.com/x.json",
		"ftp_scheme":        "ftp://example.com/x.json",
		"no_host":           "https:///x.json",
		"no_path":           "https://example.com",
		"root_path":         "https://example.com/",
		"with_query":        "https://example.com/x.json?a=1",
		"with_fragment":     "https://example.com/x.json#frag",
		"with_userinfo":     "https://user:pw@example.com/x.json",
		"wrong_port":        "https://example.com:8443/x.json",
		"dot_segment":       "https://example.com/./x.json",
		"dotdot_segment":    "https://example.com/a/../x.json",
		"encoded_dot":       "https://example.com/%2e/x.json",
		"encoded_dot_upper": "https://example.com/%2E/x.json",
		"encoded_dotdot":    "https://example.com/%2e%2e/x.json",
		"mixed_encoded":     "https://example.com/.%2e/x.json",
		"encoded_slash":     "https://example.com/a%2fb/x.json",
		"encoded_backslash": "https://example.com/a%5cb/x.json",
		"uppercase_host":    "https://Example.com/x.json",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateCIMDClientIDURL(raw); err == nil {
				t.Errorf("expected %q to fail validation", raw)
			} else if !errors.Is(err, errCIMDInvalidURL) {
				t.Errorf("expected errCIMDInvalidURL, got %v", err)
			}
		})
	}
}

func TestValidateCIMDClientIDURL_OversizeRejected(t *testing.T) {
	raw := "https://example.com/" + strings.Repeat("a", cimdMaxURLLength)
	if _, err := validateCIMDClientIDURL(raw); err == nil {
		t.Errorf("expected oversize URL to fail")
	}
}

// --- isBlockedIP --------------------------------------------------------

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
		"::1", "fe80::1", "fc00::1", "192.0.0.1",
	}
	ok := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111",
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be blocked", s)
		}
	}
	for _, s := range ok {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be allowed", s)
		}
	}
}

// --- schema validation --------------------------------------------------

func TestParseCIMDMetadata_OK(t *testing.T) {
	const u = "https://claude.ai/oauth/mcp-oauth-client-metadata"
	body := []byte(`{
		"client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
		"client_name": "Claude",
		"client_uri": "https://claude.ai",
		"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
		"grant_types": ["authorization_code","refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "none"
	}`)
	c, err := parseCIMDMetadata(u, body)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if c.TokenEndpointAuthMethod != "none" || len(c.RedirectURIs) != 1 {
		t.Errorf("unexpected client: %#v", c)
	}
}

func TestParseCIMDMetadata_Reject(t *testing.T) {
	const u = "https://x.example/y.json"
	cases := map[string]string{
		"client_id_mismatch":      `{"client_id":"https://other/x","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none"}`,
		"missing_auth_method":     `{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"]}`,
		"wrong_auth_method":       `{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
		"client_secret_present":   `{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none","client_secret":"s"}`,
		"empty_redirect_uris":     `{"client_id":"` + u + `","client_name":"X","redirect_uris":[],"token_endpoint_auth_method":"none"}`,
		"duplicate_redirect_uris": `{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb","https://x/cb"],"token_endpoint_auth_method":"none"}`,
		"http_redirect_uri":       `{"client_id":"` + u + `","client_name":"X","redirect_uris":["http://x/cb"],"token_endpoint_auth_method":"none"}`,
		"unsupported_grant":       `{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none","grant_types":["password"]}`,
		"unsupported_response":    `{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none","response_types":["token"]}`,
		"empty_name":              `{"client_id":"` + u + `","client_name":"","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none"}`,
		"oversize_name":           `{"client_id":"` + u + `","client_name":"` + strings.Repeat("a", cimdMaxClientNameLength+1) + `","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none"}`,
		"trailing_tokens":         `{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none"} extra`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCIMDMetadata(u, []byte(body)); err == nil {
				t.Errorf("expected rejection for %s", name)
			} else if !errors.Is(err, errCIMDInvalidMetadata) {
				t.Errorf("expected errCIMDInvalidMetadata, got %v", err)
			}
		})
	}
}

func TestParseCIMDMetadata_GrantTypesMustIncludeAuthCode(t *testing.T) {
	const u = "https://x.example/y.json"
	body := []byte(`{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none","grant_types":["refresh_token"]}`)
	if _, err := parseCIMDMetadata(u, body); err == nil {
		t.Errorf("expected error: grant_types without authorization_code")
	}
}

// --- fetcher / cache (end-to-end with httptest) -------------------------

// testResolver returns a cimdResolver wired against a fake DNS that always
// returns 127.0.0.1 BUT bypasses the SSRF block check by lying — for unit
// tests we want to actually talk to httptest. We achieve this by setting the
// resolveIP to return 127.0.0.1 and overriding ssrfSafeDial via the
// httpClient.Transport.DialContext to ignore the SSRF blocklist for the
// loopback test.
func testResolver(t *testing.T, server *httptest.Server) *cimdResolver {
	t.Helper()
	su, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("server URL parse: %v", err)
	}
	host, port, err := net.SplitHostPort(su.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	_ = host
	r := newCIMDResolver(nil)
	// Replace the Transport with one that always dials the httptest server
	// instead of doing real DNS. This keeps the rest of the fetch / parse /
	// cache logic exercised exactly as production.
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
		TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig,
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

// roundTrip URL — the URL the resolver "thinks" it is fetching. We point the
// transport at the real httptest server above.
func cimdTestURL(host, path string) string {
	return "https://" + host + path
}

func TestCIMDResolve_HappyPath_Cached(t *testing.T) {
	hits := int32(0)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, `{
		  "client_id": %q,
		  "client_name": "Demo",
		  "redirect_uris": ["https://demo.example.com/cb"],
		  "token_endpoint_auth_method": "none"
		}`, cimdTestURL("demo.example.com", "/x.json"))
	}))
	defer server.Close()

	r := testResolver(t, server)
	u := cimdTestURL("demo.example.com", "/x.json")

	c1, err := r.resolve(context.Background(), u)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	c2, err := r.resolve(context.Background(), u)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if c1 != c2 {
		t.Errorf("expected cached pointer reuse")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected 1 upstream fetch, got %d", hits)
	}
}

func TestCIMDResolve_NoStoreSkipsCache(t *testing.T) {
	hits := int32(0)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":["https://d.example.com/cb"],"token_endpoint_auth_method":"none"}`, cimdTestURL("d.example.com", "/x.json"))
	}))
	defer server.Close()
	r := testResolver(t, server)
	u := cimdTestURL("d.example.com", "/x.json")
	for i := 0; i < 3; i++ {
		if _, err := r.resolve(context.Background(), u); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Errorf("expected 3 fetches (no-store), got %d", hits)
	}
}

func TestCIMDResolve_MaxAgeCappedAt1Hour(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=999999999")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":["https://d.example.com/cb"],"token_endpoint_auth_method":"none"}`, cimdTestURL("d.example.com", "/x.json"))
	}))
	defer server.Close()
	r := testResolver(t, server)
	now := time.Now()
	r.now = func() time.Time { return now }
	u := cimdTestURL("d.example.com", "/x.json")
	if _, err := r.resolve(context.Background(), u); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	e, ok := r.cache.get(u, now)
	if !ok {
		t.Fatalf("expected cache entry")
	}
	if e.expiresAt.After(now.Add(cimdMaxCacheTTL + time.Second)) {
		t.Errorf("expected TTL cap, got expiresAt=%v", e.expiresAt)
	}
}

func TestCIMDResolve_OversizeBodyRejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{"))
		w.Write([]byte(strings.Repeat("a", cimdMaxBodyBytes+1)))
		w.Write([]byte("}"))
	}))
	defer server.Close()
	r := testResolver(t, server)
	_, err := r.resolve(context.Background(), cimdTestURL("d.example.com", "/x.json"))
	if err == nil || !errors.Is(err, errCIMDFetch) {
		t.Errorf("expected errCIMDFetch, got %v", err)
	}
}

func TestCIMDResolve_NonJSONRejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("not json"))
	}))
	defer server.Close()
	r := testResolver(t, server)
	_, err := r.resolve(context.Background(), cimdTestURL("d.example.com", "/x.json"))
	if err == nil || !errors.Is(err, errCIMDFetch) {
		t.Errorf("expected errCIMDFetch, got %v", err)
	}
}

func TestCIMDResolve_RedirectRejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/y.json", http.StatusFound)
	}))
	defer server.Close()
	r := testResolver(t, server)
	_, err := r.resolve(context.Background(), cimdTestURL("d.example.com", "/x.json"))
	if err == nil || !errors.Is(err, errCIMDFetch) {
		t.Errorf("expected errCIMDFetch, got %v", err)
	}
}

func TestCIMDResolve_NegativeCache(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	r := testResolver(t, server)
	u := cimdTestURL("d.example.com", "/x.json")
	if _, err := r.resolve(context.Background(), u); err == nil {
		t.Fatal("expected error")
	}
	e, ok := r.cache.get(u, time.Now())
	if !ok || e.err == nil {
		t.Errorf("expected negative cache entry")
	}
}

// --- SSRF dial directly --------------------------------------------------

func TestSSRFSafeDial_BlocksPrivateAddress(t *testing.T) {
	r := newCIMDResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.1.2.3")}, nil
	})
	_, err := r.ssrfSafeDial(context.Background(), "tcp", "evil.example:443")
	if err == nil || !errors.Is(err, errCIMDSSRFBlocked) {
		t.Errorf("expected SSRF block, got %v", err)
	}
}

func TestSSRFSafeDial_BlocksAllResolvedAddresses(t *testing.T) {
	r := newCIMDResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("169.254.169.254")}, nil
	})
	_, err := r.ssrfSafeDial(context.Background(), "tcp", "metadata.example:443")
	if err == nil || !errors.Is(err, errCIMDSSRFBlocked) {
		t.Errorf("expected SSRF block, got %v", err)
	}
}
