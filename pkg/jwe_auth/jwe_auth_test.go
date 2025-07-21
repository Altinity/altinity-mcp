package jwe_auth_test

import (
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/golang-jwt/jwe"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// TestJWETokenGeneration tests JWE token generation with TLS configuration
func TestJWETokenGeneration(t *testing.T) {
	t.Parallel()
	jweSecretKey := []byte("this-is-a-32-byte-secret-key!!") // 32 bytes for A256KW
	jwtSecretKey := []byte("test-jwt-secret")

	// Test basic JWE token generation
	t.Run("basic_token", func(t *testing.T) {
		claims := jwt.MapClaims{
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
		jweToken, err := jwe.ParseEncrypted(tokenString)
		require.NoError(t, err)
		decryptedJWT, err := jweToken.Decrypt(jweSecretKey)
		require.NoError(t, err)

		var parsedClaims jwt.MapClaims
		parsedToken, err := jwt.ParseWithClaims(string(decryptedJWT), &parsedClaims, func(token *jwt.Token) (interface{}, error) {
			require.IsType(t, &jwt.SigningMethodHMAC{}, token.Method)
			return jwtSecretKey, nil
		})
		require.NoError(t, err)
		require.True(t, parsedToken.Valid)

		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
	})
}
