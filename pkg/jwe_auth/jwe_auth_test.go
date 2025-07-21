package jwe_auth_test

import (
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/stretchr/testify/require"
)

// TestJWETokenGeneration tests JWE token generation with TLS configuration
func TestJWETokenGeneration(t *testing.T) {
	t.Parallel()
	jweSecretKey := []byte("any-jwe-secret") // Will be hashed to 32 bytes
	jwtSecretKey := []byte("any-jwt-secret") // Will be hashed to 32 bytes

	// Test basic JWE token generation
	t.Run("basic_token", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "localhost",
			"port":     float64(8123),
			"database": "default",
			"username": "default",
			"protocol": "http",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Decrypt and verify the token
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
	})
}

// TestParseAndDecryptJWE tests JWE parsing and validation
func TestParseAndDecryptJWE(t *testing.T) {
	jweSecretKey := []byte("any-jwe-secret") // Will be hashed to 32 bytes
	jwtSecretKey := []byte("any-jwt-secret") // Will be hashed to 32 bytes

	t.Run("valid_token", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "test-host",
			"port":     float64(9000),
			"database": "test-db",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedClaims["host"])
		require.Equal(t, float64(9000), parsedClaims["port"])
		require.Equal(t, "test-db", parsedClaims["database"])
	})

	t.Run("invalid_token", func(t *testing.T) {
		_, err := jwe_auth.ParseAndDecryptJWE("invalid-token", jweSecretKey, jwtSecretKey)
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})

	t.Run("expired_token", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(-time.Hour).Unix(), // Expired
		}

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		_, err = jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, jwtSecretKey)
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})
}
