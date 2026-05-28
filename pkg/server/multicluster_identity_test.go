package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCacheKey(t *testing.T) {
	t.Parallel()
	k1 := CacheKey("aaa")
	k2 := CacheKey("aaa")
	k3 := CacheKey("aab")
	require.Equal(t, k1, k2, "stable for same bearer")
	require.NotEqual(t, k1, k3, "diverges on token rotation")
	require.True(t, len(k1) > len("tok:"), "non-empty hex body")
}

func TestCacheKey_PreventsForgedClaimReuse(t *testing.T) {
	t.Parallel()
	// Two different bearer strings — even if their JWT payloads have an
	// identical email claim — must hash to different cache keys. This is
	// the v1.0 forgery defence: cache key is bound to the literal bearer
	// bytes, not to a parsed sub/email claim that an attacker could
	// match by emitting their own JWT with the same email.
	a := makeFakeJWT(t, map[string]any{"email": "alice@example.com", "sub": "user1"})
	b := makeFakeJWT(t, map[string]any{"email": "alice@example.com", "sub": "user2"})
	require.NotEqual(t, CacheKey(a), CacheKey(b))
}

func TestBearerExp_JWT(t *testing.T) {
	t.Parallel()
	want := time.Now().Add(45 * time.Minute).Unix()
	tok := makeFakeJWT(t, map[string]any{"exp": want})
	got, ok := BearerExp(tok)
	require.True(t, ok)
	require.Equal(t, want, got.Unix())
}

func TestBearerExp_FractionalExp(t *testing.T) {
	t.Parallel()
	want := float64(time.Now().Add(time.Minute).Unix()) + 0.5
	tok := makeFakeJWT(t, map[string]any{"exp": want})
	got, ok := BearerExp(tok)
	require.True(t, ok)
	require.Equal(t, int64(want), got.Unix())
}

func TestBearerExp_OpaqueAndMalformed(t *testing.T) {
	t.Parallel()
	_, ok := BearerExp("opaque-token")
	require.False(t, ok)
	_, ok = BearerExp("")
	require.False(t, ok)
	// 3 parts but bad base64
	_, ok = BearerExp("not.a.jwt")
	require.False(t, ok)
}

func TestBearerExp_NoExpClaim(t *testing.T) {
	t.Parallel()
	tok := makeFakeJWT(t, map[string]any{"email": "x@y.z"})
	_, ok := BearerExp(tok)
	require.False(t, ok)
}

func TestClassifyDiscoveryError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		err      error
		wantAuth bool
	}{
		{"nil", nil, false},
		{"401", errors.New("http 401 Unauthorized"), true},
		{"403", errors.New("http 403 Forbidden"), true},
		{"code-516", errors.New("clickhouse: code: 516, message: ..."), true},
		{"code-519", errors.New("Code: 519 NOT_ENOUGH_PRIVILEGES"), true},
		{"code-497", errors.New("Code: 497 ACCESS_DENIED"), true},
		{"deadline", context.DeadlineExceeded, false},
		{"random-500", errors.New("http 500 oops"), false},
		{"connection-refused", errors.New("connection refused"), false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			gotAuth, _ := ClassifyDiscoveryError(c.err)
			require.Equal(t, c.wantAuth, gotAuth, "err=%v", c.err)
		})
	}
}

// makeFakeJWT crafts a base64-URL-encoded fake JWT with the given claims
// (signature ignored — these helpers never validate).
func makeFakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payloadJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("nope"))
	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}
