package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"
)

// CacheKey derives the catalog cache key from a raw bearer token. Returns
// "tok:" + sha256_hex(bearer). The "tok:" prefix is purely for log
// readability — the security property is that the cache key is bound to
// the literal bearer bytes, so token rotation invalidates the cache and a
// forged claim set cannot reuse a victim's cached catalog. The cluster
// name is appended separately by the catalog cache to give a final key of
// shape "<CacheKey>\x00<cluster>".
func CacheKey(bearer string) string {
	sum := sha256.Sum256([]byte(bearer))
	return "tok:" + hex.EncodeToString(sum[:])
}

// BearerExp extracts the `exp` (RFC 7519 §4.1.4) claim from an unverified
// JWT bearer. Returns (zero, false) for opaque bearers, malformed JWTs, or
// JWTs without an exp claim. The signature is NOT validated — this is
// purely a TTL hint used to bound a positive catalog cache entry's
// expiration; the actual signature/iss/aud/exp validation is done by the
// sidecar at query time.
func BearerExp(bearer string) (time.Time, bool) {
	parts := strings.Split(strings.TrimSpace(bearer), ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return time.Time{}, false
		}
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	if claims.Exp == "" {
		return time.Time{}, false
	}
	expInt, err := claims.Exp.Int64()
	if err != nil {
		// Spec says NumericDate but tolerate fractional seconds.
		if expFloat, ferr := claims.Exp.Float64(); ferr == nil && expFloat > 0 {
			return time.Unix(int64(expFloat), 0), true
		}
		return time.Time{}, false
	}
	if expInt <= 0 {
		return time.Time{}, false
	}
	return time.Unix(expInt, 0), true
}

// DiscoveryErrorClass categorises tool-discovery errors for the catalog
// cache. Only "auth"-class errors are memoised in the negative cache;
// transient errors (timeouts, 5xx, DNS, connection refused) are deliberately
// not cached so the next request reconnects.
type DiscoveryErrorClass string

const (
	// DiscoveryAuthError indicates the user is not allowed to query this
	// cluster (HTTP 401/403 from CH, or CH-side auth-class codes 516/519/497).
	// These are memoised as a "denied" catalog entry for catalog_negative_ttl.
	DiscoveryAuthError DiscoveryErrorClass = "auth"
	// DiscoveryTransientError covers timeouts, DNS, 5xx, refused — anything
	// where retrying might succeed. Not cached.
	DiscoveryTransientError DiscoveryErrorClass = "transient"
)

// ClassifyDiscoveryError reports whether err is an auth-class failure
// (worth memoising as a denied entry in the catalog cache) or a transient
// one (not cached). The set of "auth-class" CH exception codes is
// deliberately small: 516 (AUTHENTICATION_FAILED), 519 (NOT_ENOUGH_PRIVILEGES),
// 497 (ACCESS_DENIED). Everything else falls through to transient — the
// catalog cache will not stamp out a recoverable infrastructure blip.
func ClassifyDiscoveryError(err error) (auth bool, class DiscoveryErrorClass) {
	if err == nil {
		return false, ""
	}
	msg := err.Error()

	// net/http 401/403 surfaces and embedded test rigs. Match on common
	// substrings rather than typed errors — the ClickHouse driver returns
	// wrapped errors whose underlying type varies across protocol+transport
	// combinations.
	if strings.Contains(msg, "401") || strings.Contains(msg, "Unauthorized") ||
		strings.Contains(msg, "403") || strings.Contains(msg, "Forbidden") {
		return true, DiscoveryAuthError
	}

	if strings.Contains(msg, "Token authentication is not configured") {
		return true, DiscoveryAuthError
	}

	// CH exception codes — encoded into the error text by the driver as
	// "code: NNN". Auth-class set: 497 (ACCESS_DENIED), 516
	// (AUTHENTICATION_FAILED), 519 (NOT_ENOUGH_PRIVILEGES).
	if containsCHCode(msg, 497) || containsCHCode(msg, 516) || containsCHCode(msg, 519) {
		return true, DiscoveryAuthError
	}

	// Network / timeout / DNS — explicitly transient.
	if errors.Is(err, context.DeadlineExceeded) {
		return false, DiscoveryTransientError
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return false, DiscoveryTransientError
	}

	// Default: treat unknown as transient. Better to refetch than to
	// stamp out a flaky backend with a cached "denied".
	return false, DiscoveryTransientError
}

// containsCHCode reports whether msg contains a ClickHouse exception code
// of the shape "code: NNN" or "Code: NNN" — emitted by both the native
// and HTTP drivers in the error text.
func containsCHCode(msg string, code int) bool {
	needle := "code: "
	idx := strings.Index(strings.ToLower(msg), needle)
	if idx < 0 {
		return false
	}
	tail := msg[idx+len(needle):]
	if len(tail) < 3 {
		return false
	}
	// Compare the leading digits to code.
	digits := 0
	for digits < len(tail) && tail[digits] >= '0' && tail[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return false
	}
	parsed := 0
	for i := 0; i < digits; i++ {
		parsed = parsed*10 + int(tail[i]-'0')
	}
	return parsed == code
}
