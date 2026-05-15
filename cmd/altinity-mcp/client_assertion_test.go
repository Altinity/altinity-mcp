package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// --- CIMD parser: private_key_jwt path ----------------------------------

func TestParseCIMDMetadata_PrivateKeyJWT_OK(t *testing.T) {
	const u = "https://chatgpt.com/oauth/abc/client.json"
	body := []byte(`{
		"client_id": "https://chatgpt.com/oauth/abc/client.json",
		"client_name": "ChatGPT",
		"redirect_uris": ["https://chatgpt.com/connector/oauth/abc"],
		"grant_types": ["authorization_code","refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "RS256",
		"jwks_uri": "https://chatgpt.com/oauth/jwks.json"
	}`)
	c, err := parseCIMDMetadata(u, body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Errorf("auth_method = %q, want private_key_jwt", c.TokenEndpointAuthMethod)
	}
	if c.JWKSURI != "https://chatgpt.com/oauth/jwks.json" {
		t.Errorf("jwks_uri = %q", c.JWKSURI)
	}
}

func TestParseCIMDMetadata_PrivateKeyJWT_RejectMissingJWKSURI(t *testing.T) {
	const u = "https://x.example/y.json"
	body := []byte(`{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"private_key_jwt"}`)
	if _, err := parseCIMDMetadata(u, body); err == nil || !errors.Is(err, errCIMDInvalidMetadata) {
		t.Errorf("expected errCIMDInvalidMetadata, got %v", err)
	}
}

func TestParseCIMDMetadata_PrivateKeyJWT_RejectBadJWKSURI(t *testing.T) {
	const u = "https://x.example/y.json"
	cases := map[string]string{
		"http":     `"http://x/jwks.json"`,
		"loopback": `"https://127.0.0.1/jwks.json"`, // not blocked at parse — SSRF caught at dial
		"userinfo": `"https://u:p@x/jwks.json"`,
		"empty":    `""`,
	}
	for name, jwksJSON := range cases {
		t.Run(name, func(t *testing.T) {
			body := []byte(`{"client_id":"` + u + `","client_name":"X","redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":` + jwksJSON + `}`)
			_, err := parseCIMDMetadata(u, body)
			switch name {
			case "loopback":
				if err != nil {
					t.Errorf("loopback jwks_uri must pass parse (SSRF caught at dial), got %v", err)
				}
			default:
				if err == nil || !errors.Is(err, errCIMDInvalidMetadata) {
					t.Errorf("expected errCIMDInvalidMetadata, got %v", err)
				}
			}
		})
	}
}

// --- client_assertion verification -------------------------------------

type testClient struct {
	key     *rsa.PrivateKey
	keyID   string
	jwks    *jose.JSONWebKeySet
	jwksSrv *httptest.Server
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const kid = "test-kid-1"
	pub := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return &testClient{key: priv, keyID: kid, jwks: jwks, jwksSrv: srv}
}

func (tc *testClient) sign(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: tc.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", tc.keyID),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// testApp builds an *application with a cimdResolver whose http client dials
// the JWKS httptest server via 127.0.0.1, mirroring testResolver.
func testApp(t *testing.T, jwksSrv *httptest.Server, fixedNow time.Time) *application {
	t.Helper()
	su, err := url.Parse(jwksSrv.URL)
	if err != nil {
		t.Fatalf("server URL parse: %v", err)
	}
	_, port, err := net.SplitHostPort(su.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	r := newCIMDResolver(nil)
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
		TLSClientConfig: jwksSrv.Client().Transport.(*http.Transport).TLSClientConfig,
	}
	r.httpClient = &http.Client{
		Transport: tr,
		Timeout:   cimdFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	r.now = func() time.Time { return fixedNow }
	return &application{cimdResolver: r}
}

func TestVerifyClientAssertion_Happy(t *testing.T) {
	const (
		clientID = "https://chatgpt.com/oauth/abc/client.json"
		tokenURL = "https://mcp.example.com/oauth/token"
	)
	tc := newTestClient(t)
	now := time.Now()
	app := testApp(t, tc.jwksSrv, now)
	client := &statelessRegisteredClient{
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 tc.jwksSrv.URL + "/jwks.json", // host irrelevant; tr dials 127.0.0.1
	}
	jwt := tc.sign(t, jwt.Claims{
		Issuer:   clientID,
		Subject:  clientID,
		Audience: []string{tokenURL},
		Expiry:   jwtNumeric(now.Add(2 * time.Minute)),
		IssuedAt: jwtNumeric(now),
	})
	if err := app.verifyClientAssertion(context.Background(), client, clientID, jwt, tokenURL); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyClientAssertion_Reject(t *testing.T) {
	const (
		clientID = "https://chatgpt.com/oauth/abc/client.json"
		tokenURL = "https://mcp.example.com/oauth/token"
	)
	tc := newTestClient(t)
	now := time.Now()
	app := testApp(t, tc.jwksSrv, now)
	client := &statelessRegisteredClient{
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 tc.jwksSrv.URL + "/jwks.json",
	}

	cases := map[string]jwt.Claims{
		"wrong_iss": {Issuer: "https://other/", Subject: clientID, Audience: []string{tokenURL}, Expiry: jwtNumeric(now.Add(time.Minute)), IssuedAt: jwtNumeric(now)},
		"wrong_sub": {Issuer: clientID, Subject: "https://other/", Audience: []string{tokenURL}, Expiry: jwtNumeric(now.Add(time.Minute)), IssuedAt: jwtNumeric(now)},
		"wrong_aud": {Issuer: clientID, Subject: clientID, Audience: []string{"https://other/oauth/token"}, Expiry: jwtNumeric(now.Add(time.Minute)), IssuedAt: jwtNumeric(now)},
		"expired":   {Issuer: clientID, Subject: clientID, Audience: []string{tokenURL}, Expiry: jwtNumeric(now.Add(-2 * time.Minute)), IssuedAt: jwtNumeric(now.Add(-3 * time.Minute))},
		"over_lifetime": {
			Issuer: clientID, Subject: clientID, Audience: []string{tokenURL},
			IssuedAt: jwtNumeric(now),
			Expiry:   jwtNumeric(now.Add(clientAssertionMaxLifetime + time.Minute)),
		},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			tok := tc.sign(t, claims)
			err := app.verifyClientAssertion(context.Background(), client, clientID, tok, tokenURL)
			if err == nil {
				t.Errorf("expected rejection, got nil")
			} else if !errors.Is(err, errClientAssertionInvalid) {
				t.Errorf("expected errClientAssertionInvalid, got %v", err)
			}
		})
	}
}

func TestVerifyClientAssertion_TamperedSignature(t *testing.T) {
	const (
		clientID = "https://chatgpt.com/oauth/abc/client.json"
		tokenURL = "https://mcp.example.com/oauth/token"
	)
	tc := newTestClient(t)
	now := time.Now()
	app := testApp(t, tc.jwksSrv, now)
	client := &statelessRegisteredClient{
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 tc.jwksSrv.URL + "/jwks.json",
	}
	tok := tc.sign(t, jwt.Claims{
		Issuer: clientID, Subject: clientID, Audience: []string{tokenURL},
		Expiry: jwtNumeric(now.Add(time.Minute)), IssuedAt: jwtNumeric(now),
	})
	// Flip a character in the signature segment.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("bad JWT shape")
	}
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	tampered := strings.Join(parts, ".")
	err := app.verifyClientAssertion(context.Background(), client, clientID, tampered, tokenURL)
	if err == nil || !errors.Is(err, errClientAssertionInvalid) {
		t.Errorf("expected errClientAssertionInvalid on tampered signature, got %v", err)
	}
}

func TestVerifyClientAssertion_MissingJWKSURI(t *testing.T) {
	client := &statelessRegisteredClient{TokenEndpointAuthMethod: "private_key_jwt"}
	app := &application{cimdResolver: newCIMDResolver(nil)}
	err := app.verifyClientAssertion(context.Background(), client, "https://x/", "x.y.z", "https://x/token")
	if err == nil || !errors.Is(err, errClientAssertionInvalid) {
		t.Errorf("expected rejection on missing jwks_uri, got %v", err)
	}
}

func TestVerifyClientAssertion_KidRotation(t *testing.T) {
	const (
		clientID = "https://chatgpt.com/oauth/abc/client.json"
		tokenURL = "https://mcp.example.com/oauth/token"
	)
	// Two keys, only the second is published initially. First request fills
	// the cache with key2 only. Then we sign with key1 → kid miss → cache
	// invalidate → re-fetch (still only key2) → final rejection.
	tc := newTestClient(t)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)
	const otherKid = "rotated-kid"
	now := time.Now()
	app := testApp(t, tc.jwksSrv, now)
	client := &statelessRegisteredClient{
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 tc.jwksSrv.URL + "/jwks.json",
	}
	// Sign with priv2 / otherKid (not in JWKS).
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv2},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", otherKid))
	tok, _ := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: clientID, Subject: clientID, Audience: []string{tokenURL},
		Expiry: jwtNumeric(now.Add(time.Minute)), IssuedAt: jwtNumeric(now),
	}).Serialize()
	err := app.verifyClientAssertion(context.Background(), client, clientID, tok, tokenURL)
	if err == nil {
		t.Errorf("expected rejection (kid not in JWKS), got nil")
	}
}

// --- helpers -----------------------------------------------------------

func jwtNumeric(t time.Time) *jwt.NumericDate {
	n := jwt.NewNumericDate(t)
	return n
}

// keep imports used even if some helpers become unused later
var _ = fmt.Sprintf
