// synthetic-idp — a controllable OIDC IdP for ch-jwt-verify stress testing.
//
// NOT FOR PRODUCTION. Mints RS256 JWTs on demand. Serves OIDC discovery and
// JWKS endpoints. Exposes operational verbs to rotate keys, break the JWKS
// endpoint, and slow it down — the knobs the HA test plan
// (~/tmp/ha-test-plan-pr128.md) needs.
//
// Endpoints (all plain HTTP, in-cluster only):
//
//	GET  /.well-known/openid-configuration   — issuer + jwks_uri discovery
//	GET  /.well-known/jwks.json              — current JWKS (may be slowed/broken)
//	POST /sign                               — mint a JWT, query params:
//	                                             email    (default loadtest@example.com)
//	                                             aud      (default $AUDIENCE)
//	                                             kid      (default current active kid)
//	                                             exp      (seconds from now, default 300)
//	                                             iat_off  (offset from now, signed, default 0)
//	                                             nbf_off  (offset from now, signed, default 0)
//	                                             email_verified (default true)
//	POST /rotate?kid=<id>                    — add a new RSA key with this kid; becomes current.
//	POST /retire?kid=<id>                    — remove a kid from the JWKS but keep the key in memory.
//	POST /jwks/break?on=true|false           — toggle JWKS 503.
//	POST /jwks/slow?ms=N                     — set JWKS response delay.
//	GET  /healthz                            — k8s liveness.
//
// Configuration via env:
//
//	ISSUER     — issuer URL claim and discovery `issuer`. Default
//	             http://synthetic-idp.demo.svc.cluster.local/.
//	AUDIENCE   — default audience claim for /sign. Default https://otel-mcp.test/.
//	LISTEN     — address to bind. Default :80.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	issuerURL = envDefault("ISSUER", "http://synthetic-idp.demo.svc.cluster.local/")
	audience  = envDefault("AUDIENCE", "https://otel-mcp.test/")
	listen    = envDefault("LISTEN", ":80")

	mu         sync.RWMutex
	keys       = map[string]*rsa.PrivateKey{} // all keys ever minted
	publicKids = map[string]bool{}             // kids advertised in /jwks
	activeKid  = "k1"                          // default kid for /sign

	jwksBreak atomic.Bool
	jwksSlow  atomic.Int64
)

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mintKey(kid string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	mu.Lock()
	keys[kid] = priv
	publicKids[kid] = true
	activeKid = kid
	mu.Unlock()
	return nil
}

func currentJWKS() jose.JSONWebKeySet {
	mu.RLock()
	defer mu.RUnlock()
	set := jose.JSONWebKeySet{}
	for kid := range publicKids {
		k := keys[kid]
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       &k.PublicKey,
			KeyID:     kid,
			Algorithm: "RS256",
			Use:       "sig",
		})
	}
	return set
}

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                strings.TrimSuffix(issuerURL, "/"),
		"jwks_uri":                              strings.TrimSuffix(issuerURL, "/") + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if ms := jwksSlow.Load(); ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
	if jwksBreak.Load() {
		http.Error(w, "jwks broken (synthetic)", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(currentJWKS())
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	email := q.Get("email")
	if email == "" {
		email = "loadtest@example.com"
	}
	aud := q.Get("aud")
	if aud == "" {
		aud = audience
	}
	kid := q.Get("kid")
	expSec := atoiOr(q.Get("exp"), 300)
	iatOff := atoiOr(q.Get("iat_off"), 0)
	nbfOff := atoiOr(q.Get("nbf_off"), 0)
	emailVerified := q.Get("email_verified") != "false"

	mu.RLock()
	if kid == "" {
		kid = activeKid
	}
	priv, ok := keys[kid]
	mu.RUnlock()
	if !ok {
		http.Error(w, "unknown kid: "+kid, http.StatusBadRequest)
		return
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":            strings.TrimSuffix(issuerURL, "/") + "/",
		"aud":            aud,
		"email":          email,
		"email_verified": emailVerified,
		"sub":            email,
		"iat":            now + int64(iatOff),
		"nbf":            now + int64(nbfOff),
		"exp":            now + int64(expSec),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(tok))
}

func rotateHandler(w http.ResponseWriter, r *http.Request) {
	kid := r.URL.Query().Get("kid")
	if kid == "" {
		kid = fmt.Sprintf("k%d", time.Now().UnixNano())
	}
	if err := mintKey(kid); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "rotated to kid=%s\n", kid)
}

func retireHandler(w http.ResponseWriter, r *http.Request) {
	kid := r.URL.Query().Get("kid")
	if kid == "" {
		http.Error(w, "kid required", http.StatusBadRequest)
		return
	}
	mu.Lock()
	delete(publicKids, kid) // private key retained so previously issued tokens still validate if re-published
	mu.Unlock()
	fmt.Fprintf(w, "retired kid=%s from JWKS (private key kept)\n", kid)
}

func breakHandler(w http.ResponseWriter, r *http.Request) {
	on := r.URL.Query().Get("on") == "true"
	jwksBreak.Store(on)
	fmt.Fprintf(w, "jwks_break=%v\n", on)
}

func slowHandler(w http.ResponseWriter, r *http.Request) {
	ms := atoiOr(r.URL.Query().Get("ms"), 0)
	jwksSlow.Store(int64(ms))
	fmt.Fprintf(w, "jwks_slow=%d ms\n", ms)
}

func healthHandler(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func main() {
	if err := mintKey("k1"); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", discoveryHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("/sign", signHandler)
	mux.HandleFunc("/rotate", rotateHandler)
	mux.HandleFunc("/retire", retireHandler)
	mux.HandleFunc("/jwks/break", breakHandler)
	mux.HandleFunc("/jwks/slow", slowHandler)
	mux.HandleFunc("/healthz", healthHandler)

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("synthetic-idp listening on %s, issuer=%s, audience=%s", listen, issuerURL, audience)
	log.Fatal(srv.ListenAndServe())
}
