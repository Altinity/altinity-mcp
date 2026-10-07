package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/go-mcp-oauth-sdk/jwe_auth"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const jweTokenGeneratorBodyLimit = 64 << 10

type jweTokenGeneratorRequest struct {
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	Database              string `json:"database"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	Protocol              string `json:"protocol"`
	Expiry                int    `json:"expiry"`
	Limit                 int    `json:"limit,omitempty"`
	TLSEnabled            bool   `json:"tls_enabled,omitempty"`
	TLSCaCert             string `json:"tls_ca_cert,omitempty"`
	TLSClientCert         string `json:"tls_client_cert,omitempty"`
	TLSClientKey          string `json:"tls_client_key,omitempty"`
	TLSInsecureSkipVerify bool   `json:"tls_insecure_skip_verify,omitempty"`
}

// serveJWETokenGenerator snapshots configuration once for authorization and issuance.
func (a *application) serveJWETokenGenerator(w http.ResponseWriter, r *http.Request) {
	serveJWETokenGeneration(w, r, a.GetCurrentConfig().Server.JWE, log.Logger)
}

func serveJWETokenGeneration(w http.ResponseWriter, r *http.Request, cfg config.JWEConfig, logger zerolog.Logger) {
	if !cfg.Enabled || !cfg.TokenGenerator.Enabled {
		http.NotFound(w, r)
		return
	}
	// Fail closed even if a caller bypassed initial/reload configuration validation.
	header := r.Header.Get("Authorization")
	scheme, supplied, ok := strings.Cut(header, " ")
	if len(cfg.TokenGenerator.AdminToken) < 32 || !ok || !strings.EqualFold(scheme, "Bearer") ||
		subtle.ConstantTimeCompare([]byte(supplied), []byte(cfg.TokenGenerator.AdminToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cfg.JWESecretKey == "" {
		http.Error(w, "Missing JWE secret key", http.StatusInternalServerError)
		return
	}

	// Read the whole bounded body before decoding: oversized malformed JSON and
	// oversized trailing whitespace must receive the same 413 as valid JSON.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, jweTokenGeneratorBodyLimit))
	if err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
		}
		return
	}
	var request jweTokenGeneratorRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Host) == "" || strings.TrimSpace(request.Username) == "" {
		http.Error(w, "jwe: token must carry host and username claims", http.StatusBadRequest)
		return
	}
	if request.Expiry == 0 {
		request.Expiry = 3600
	}
	if request.Expiry < 0 || request.Expiry > cfg.TokenGenerator.EffectiveMaxExpirySeconds() {
		http.Error(w, "expiry must be positive and within max_expiry_seconds", http.StatusBadRequest)
		return
	}
	now := time.Now().Unix()
	if int64(request.Expiry) > math.MaxInt64-now {
		http.Error(w, "expiry is too large", http.StatusBadRequest)
		return
	}
	claims := map[string]interface{}{
		"exp":      now + int64(request.Expiry),
		"host":     request.Host,
		"username": request.Username,
	}
	if request.Port > 0 {
		claims["port"] = request.Port
	}
	if request.Database != "" {
		claims["database"] = request.Database
	}
	if request.Password != "" {
		claims["password"] = request.Password
	}
	if request.Protocol != "" {
		claims["protocol"] = request.Protocol
	}
	if request.Limit > 0 {
		claims["limit"] = request.Limit
	}
	// Validate file claims even when TLS is disabled. Only resolved paths are minted.
	for name, path := range map[string]string{
		"tls_ca_cert":     request.TLSCaCert,
		"tls_client_cert": request.TLSClientCert,
		"tls_client_key":  request.TLSClientKey,
	} {
		resolved, err := cfg.ValidateTLSMaterialPath(path)
		if err != nil {
			http.Error(w, "jwe: invalid TLS material path", http.StatusBadRequest)
			return
		}
		if resolved != "" {
			claims[name] = resolved
		}
	}
	if request.TLSEnabled {
		claims["tls_enabled"] = true
		if request.TLSInsecureSkipVerify {
			claims["tls_insecure_skip_verify"] = true
		}
	}
	token, err := jwe_auth.GenerateJWEToken(claims, []byte(cfg.JWESecretKey), []byte(cfg.JWTSecretKey))
	if err != nil {
		// Do not log encryption errors: library error contents are not a secrecy boundary.
		logger.Error().Msg("Failed to generate JWE token")
		http.Error(w, "Failed to generate JWE token", http.StatusInternalServerError)
		return
	}
	logger.Info().Str("host", request.Host).Str("username", request.Username).
		Int("expiry", request.Expiry).Msg("Issued JWE token")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}
