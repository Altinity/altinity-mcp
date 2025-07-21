package jwe_auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/golang-jwt/jwe"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// Helper functions for generating and encoding RSA keys for tests
func generateRSAKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func pemEncodePrivateKey(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func pemEncodePublicKey(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}))
}

// TestJWETokenGeneration tests JWE token generation with TLS configuration
func TestJWETokenGeneration(t *testing.T) {
	t.Parallel()
	jwePrivateKey, jwePublicKey := generateRSAKeys(t)
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

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jwePublicKey, jwtSecretKey)
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Decrypt and verify the token
		jweToken, err := jwe.ParseEncrypted(tokenString)
		require.NoError(t, err)
		decryptedJWT, err := jweToken.Decrypt(jwePrivateKey)
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
