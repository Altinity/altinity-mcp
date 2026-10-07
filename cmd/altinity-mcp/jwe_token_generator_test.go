package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/go-mcp-oauth-sdk/jwe_auth"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const fakeGeneratorAdmin = "fake-generator-admin-32-byte-secret"

func protectedGeneratorConfig() config.JWEConfig {
	return config.JWEConfig{Enabled: true, JWESecretKey: "fake-jwe-key", JWTSecretKey: "fake-jwt-key",
		TokenGenerator: config.JWETokenGeneratorConfig{Enabled: true, AdminToken: fakeGeneratorAdmin}}
}

func callProtectedGenerator(cfg config.JWEConfig, method, body, authorization string, logger zerolog.Logger) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/jwe-token-generator", strings.NewReader(body))
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	serveJWETokenGeneration(w, r, cfg, logger)
	return w
}

func decodeGeneratedClaims(t *testing.T, cfg config.JWEConfig, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var response map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	claims, err := jwe_auth.ParseAndDecryptJWE(response["token"], []byte(cfg.JWESecretKey), []byte(cfg.JWTSecretKey))
	require.NoError(t, err)
	return claims
}

func TestProtectedJWETokenGeneratorAuthorization(t *testing.T) {
	cfg := protectedGeneratorConfig()
	body := `{"host":"ch.example","username":"alice"}`
	for _, tt := range []struct {
		name, authorization string
		status              int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong same length", "Bearer " + strings.Repeat("x", len(fakeGeneratorAdmin)), http.StatusUnauthorized},
		{"wrong short", "Bearer short", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + fakeGeneratorAdmin, http.StatusUnauthorized},
		{"extra whitespace", "Bearer  " + fakeGeneratorAdmin, http.StatusUnauthorized},
		{"correct", "Bearer " + fakeGeneratorAdmin, http.StatusOK},
		{"case insensitive scheme", "bearer " + fakeGeneratorAdmin, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rr := callProtectedGenerator(cfg, http.MethodPost, body, tt.authorization, zerolog.Nop())
			require.Equal(t, tt.status, rr.Code)
			if tt.status == http.StatusUnauthorized {
				require.Equal(t, "Bearer", rr.Header().Get("WWW-Authenticate"))
				require.NotContains(t, rr.Body.String(), fakeGeneratorAdmin)
			}
		})
	}
	for _, jweEnabled := range []bool{true, false} {
		for _, generatorEnabled := range []bool{true, false} {
			if jweEnabled && generatorEnabled {
				continue
			}
			for _, key := range []string{"", "fake-key"} {
				cfg.Enabled, cfg.TokenGenerator.Enabled, cfg.JWESecretKey = jweEnabled, generatorEnabled, key
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					require.Equal(t, http.StatusNotFound, callProtectedGenerator(cfg, method, body, "", zerolog.Nop()).Code)
				}
			}
		}
	}
	cfg = protectedGeneratorConfig()
	cfg.TokenGenerator.AdminToken = "short"
	require.Equal(t, http.StatusUnauthorized, callProtectedGenerator(cfg, http.MethodPost, body, "Bearer short", zerolog.Nop()).Code)
	cfg = protectedGeneratorConfig()
	rr := callProtectedGenerator(cfg, http.MethodGet, body, "Bearer "+fakeGeneratorAdmin, zerolog.Nop())
	require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	require.Equal(t, http.MethodPost, rr.Header().Get("Allow"))
}

func TestProtectedJWETokenGeneratorBodyAndExpiry(t *testing.T) {
	cfg := protectedGeneratorConfig()
	valid := `{"host":"ch.example","username":"alice"}`
	for _, tt := range []struct {
		name, body  string
		max, status int
	}{
		{"default expiry", valid, 0, http.StatusOK},
		{"exact max expiry", `{"host":"ch.example","username":"alice","expiry":86400}`, 0, http.StatusOK},
		{"above max", `{"host":"ch.example","username":"alice","expiry":86401}`, 0, http.StatusBadRequest},
		{"negative", `{"host":"ch.example","username":"alice","expiry":-1}`, 0, http.StatusBadRequest},
		{"custom max", `{"host":"ch.example","username":"alice","expiry":1234}`, 1234, http.StatusOK},
		{"default exceeds max", valid, 1234, http.StatusBadRequest},
		{"overflow expiry", `{"host":"ch.example","username":"alice","expiry":9223372036854775807}`, math.MaxInt, http.StatusBadRequest},
		{"missing host", `{"username":"alice"}`, 0, http.StatusBadRequest},
		{"missing username", `{"host":"ch.example"}`, 0, http.StatusBadRequest},
		{"null", `null`, 0, http.StatusBadRequest},
		{"invalid JSON", `not-json`, 0, http.StatusBadRequest},
		{"two objects", valid + valid, 0, http.StatusBadRequest},
		{"trailing null", valid + `null`, 0, http.StatusBadRequest},
		{"trailing invalid", valid + `!`, 0, http.StatusBadRequest},
		{"exact body cap", valid + strings.Repeat(" ", jweTokenGeneratorBodyLimit-len(valid)), 0, http.StatusOK},
		{"oversized whitespace", valid + strings.Repeat(" ", jweTokenGeneratorBodyLimit), 0, http.StatusRequestEntityTooLarge},
		{"oversized invalid", strings.Repeat("!", jweTokenGeneratorBodyLimit+1), 0, http.StatusRequestEntityTooLarge},
		{"oversized valid", `{"host":"ch.example","username":"alice","password":"` + strings.Repeat("x", jweTokenGeneratorBodyLimit) + `"}`, 0, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg.TokenGenerator.MaxExpirySeconds = tt.max
			rr := callProtectedGenerator(cfg, http.MethodPost, tt.body, "Bearer "+fakeGeneratorAdmin, zerolog.Nop())
			require.Equal(t, tt.status, rr.Code, rr.Body.String())
			if tt.name == "default expiry" {
				claims := decodeGeneratedClaims(t, cfg, rr)
				require.InDelta(t, time.Now().Unix()+3600, claims["exp"], 2)
			}
		})
	}
}

func TestProtectedJWETokenGeneratorTLSPaths(t *testing.T) {
	root := t.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	outside := t.TempDir()
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte("fake TLS material"), 0600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(outside, "outside.pem"), []byte("fake outside material"), 0600))
	require.NoError(t, os.Symlink(filepath.Join(outside, "outside.pem"), filepath.Join(root, "escape.pem")))
	require.NoError(t, os.Symlink(filepath.Join(root, "ca.pem"), filepath.Join(root, "alias.pem")))
	for _, field := range []string{"tls_ca_cert", "tls_client_cert", "tls_client_key"} {
		for _, enabled := range []bool{false, true} {
			for _, tt := range []struct {
				name, path, dir string
				status          int
			}{
				{"no allowlist", filepath.Join(root, "ca.pem"), "", http.StatusBadRequest},
				{"relative", "ca.pem", root, http.StatusBadRequest},
				{"outside", filepath.Join(outside, "outside.pem"), root, http.StatusBadRequest},
				{"traversal", root + "/../" + filepath.Base(root) + "/ca.pem", root, http.StatusBadRequest},
				{"symlink escape", filepath.Join(root, "escape.pem"), root, http.StatusBadRequest},
				{"allowed", filepath.Join(root, "ca.pem"), root, http.StatusOK},
				{"resolved allowed", filepath.Join(root, "alias.pem"), root, http.StatusOK},
			} {
				t.Run(field+"/"+tt.name+"/"+map[bool]string{true: "TLS", false: "no TLS"}[enabled], func(t *testing.T) {
					cfg := protectedGeneratorConfig()
					cfg.TLSMaterialDir = tt.dir
					request := map[string]interface{}{"host": "ch.example", "username": "alice", "tls_enabled": enabled, field: tt.path}
					body, err := json.Marshal(request)
					require.NoError(t, err)
					rr := callProtectedGenerator(cfg, http.MethodPost, string(body), "Bearer "+fakeGeneratorAdmin, zerolog.Nop())
					require.Equal(t, tt.status, rr.Code)
					if tt.status == http.StatusOK {
						require.Equal(t, filepath.Join(resolvedRoot, "ca.pem"), decodeGeneratedClaims(t, cfg, rr)[field])
					} else {
						require.NotContains(t, rr.Body.String(), tt.path)
						require.NotContains(t, rr.Body.String(), "fake outside material")
					}
				})
			}
		}
	}
}

func TestProtectedJWETokenGeneratorIssuanceLog(t *testing.T) {
	initialLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(initialLevel) })
	cfg := protectedGeneratorConfig()
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	body := `{"host":"ch.example","port":8443,"database":"db","username":"alice","password":"fake-password-sensitive","protocol":"http","expiry":600,"limit":5,"tls_enabled":true,"tls_insecure_skip_verify":true}`
	rr := callProtectedGenerator(cfg, http.MethodPost, body, "Bearer "+fakeGeneratorAdmin, logger)
	claims := decodeGeneratedClaims(t, cfg, rr)
	require.Equal(t, "fake-password-sensitive", claims["password"])
	require.Equal(t, "http", claims["protocol"])
	require.Equal(t, "db", claims["database"])
	require.EqualValues(t, 8443, claims["port"])
	require.EqualValues(t, 5, claims["limit"])
	require.Equal(t, true, claims["tls_enabled"])
	require.Equal(t, true, claims["tls_insecure_skip_verify"])
	require.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	var event map[string]interface{}
	require.NoError(t, json.Unmarshal(output.Bytes(), &event))
	require.Equal(t, map[string]interface{}{"level": "info", "message": "Issued JWE token", "host": "ch.example", "username": "alice", "expiry": float64(600)}, event)
	for _, secret := range []string{fakeGeneratorAdmin, "fake-password-sensitive", cfg.JWESecretKey, cfg.JWTSecretKey} {
		require.NotContains(t, output.String(), secret)
	}
	var response map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	require.NotContains(t, output.String(), response["token"])
	output.Reset()
	require.Equal(t, http.StatusBadRequest, callProtectedGenerator(cfg, http.MethodPost, body+"null", "Bearer "+fakeGeneratorAdmin, logger).Code)
	require.Empty(t, output.String())
}

func TestProtectedJWETokenGeneratorRejectsBlankConnectionClaims(t *testing.T) {
	initialLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(initialLevel) })
	for _, field := range []string{"host", "username"} {
		for _, value := range []string{" ", "\t\r\n", "\u00a0", "\u2003", " \t\u00a0\u2003\n"} {
			t.Run(field+"/"+fmt.Sprintf("%q", value), func(t *testing.T) {
				claims := map[string]string{"host": "ch.example", "username": "alice"}
				claims[field] = value
				body, err := json.Marshal(claims)
				require.NoError(t, err)
				var output bytes.Buffer
				logger := zerolog.New(&output).Level(zerolog.InfoLevel)
				rr := callProtectedGenerator(protectedGeneratorConfig(), http.MethodPost, string(body), "Bearer "+fakeGeneratorAdmin, logger)
				require.Equal(t, http.StatusBadRequest, rr.Code)
				require.Equal(t, "jwe: token must carry host and username claims\n", rr.Body.String())
				require.NotContains(t, rr.Body.String(), `"token"`)
				require.Empty(t, output.String(), "rejected blank claims must not produce an issuance log")
			})
		}
	}
}
