package jwe_auth_test

import (
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/go-jose/go-jose/v4"
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

	// Test JWE token generation with empty JWT secret key
	t.Run("empty_jwt_secret_key", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "localhost",
			"port":     float64(8123),
			"database": "default",
			"username": "default",
			"protocol": "http",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		// Generate token with empty JWT secret key
		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, []byte{})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Decrypt and verify the token with empty JWT secret key
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, []byte{})
		require.NoError(t, err)

		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
		require.Equal(t, "default", parsedClaims["database"])
		require.Equal(t, "default", parsedClaims["username"])
		require.Equal(t, "http", parsedClaims["protocol"])
	})
}

// parseJWEForTesting is a helper function for testing that parses a JWE token
func parseJWEForTesting(token string) (*jose.JSONWebEncryption, error) {
	return jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.A256KW}, []jose.ContentEncryption{jose.A256GCM})
}

// regenerateJWEForTesting is a helper function for testing that regenerates a JWE token
func regenerateJWEForTesting(jweObject *jose.JSONWebEncryption, jweSecretKey []byte) (string, error) {
	hashedJWEKey := jwe_auth.HashToKeyForTesting(jweSecretKey)
	plaintext, err := jweObject.Decrypt(hashedJWEKey)
	if err != nil {
		return "", err
	}

	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256KW, Key: hashedJWEKey},
		&jose.EncrypterOptions{},
	)
	if err != nil {
		return "", err
	}

	newJWE, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	return newJWE.CompactSerialize()
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

	// Test parsing with empty JWT secret key
	t.Run("valid_token_empty_jwt_secret", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "test-host",
			"port":     float64(9000),
			"database": "test-db",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		// Generate token with empty JWT secret key
		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, []byte{})
		require.NoError(t, err)

		// Parse with empty JWT secret key
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, []byte{})
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedClaims["host"])
		require.Equal(t, float64(9000), parsedClaims["port"])
		require.Equal(t, "test-db", parsedClaims["database"])
	})

	// Test expired token with empty JWT secret key
	t.Run("expired_token_empty_jwt_secret", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(-time.Hour).Unix(), // Expired
		}

		// Generate token with empty JWT secret key
		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, []byte{})
		require.NoError(t, err)

		// Parse with empty JWT secret key - should fail due to expiration
		_, err = jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, []byte{})
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})

	// Test parsing with invalid content type
	t.Run("invalid_content_type", func(t *testing.T) {
		// Create a token with invalid content type manually
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		// Generate a valid token first
		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		// Parse and modify the JWE header to have an invalid content type
		jweObject, err := jwe_auth.ParseJWEForTesting(tokenString)
		require.NoError(t, err)

		// Set an invalid content type
		jweObject.Header.ExtraHeaders["cty"] = "INVALID"

		// Re-encrypt with invalid content type
		invalidToken, err := jwe_auth.RegenerateJWEForTesting(jweObject, jweSecretKey)
		require.NoError(t, err)

		// Should still be able to parse it (falls back to default case)
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(invalidToken, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedClaims["host"])
	})

	// Test with disallowed claim key
	t.Run("disallowed_claim_key", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":    "test-host",
			"invalid": "not-allowed", // This key is not in the whitelist
			"exp":     time.Now().Add(time.Hour).Unix(),
		}

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		_, err = jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, jwtSecretKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid token claims format")
	})

	// Test with invalid expiration type
	t.Run("invalid_exp_type", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  "not-a-number", // Invalid type for exp
		}

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		_, err = jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, jwtSecretKey)
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})

	// Test with disallowed claim key
	t.Run("disallowed_claim_key", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":    "test-host",
			"invalid": "not-allowed", // This key is not in the whitelist
			"exp":     time.Now().Add(time.Hour).Unix(),
		}

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		_, err = jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, jwtSecretKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid token claims format")
	})

	// Test with invalid expiration type
	t.Run("invalid_exp_type", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  "not-a-number", // Invalid type for exp
		}

		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		_, err = jwe_auth.ParseAndDecryptJWE(tokenString, jweSecretKey, jwtSecretKey)
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})

	// Test parsing with invalid content type
	t.Run("invalid_content_type", func(t *testing.T) {
		// Create a token with invalid content type manually
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		// Generate a valid token first
		tokenString, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		// Parse and modify the JWE header to have an invalid content type
		jweObject, err := parseJWEForTesting(tokenString)
		require.NoError(t, err)

		// Set an invalid content type
		jweObject.Header.ExtraHeaders["cty"] = "INVALID"

		// Re-encrypt with invalid content type
		invalidToken, err := regenerateJWEForTesting(jweObject, jweSecretKey)
		require.NoError(t, err)

		// Should still be able to parse it (falls back to default case)
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(invalidToken, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedClaims["host"])
	})

	// Test distinction between JWT-signed and JSON-encrypted tokens
	t.Run("distinguish_jwt_and_json_tokens", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		// Generate JWT-signed token (with JWT secret key)
		jwtToken, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		// Generate JSON-encrypted token (without JWT secret key)
		jsonToken, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, []byte{})
		require.NoError(t, err)

		// Verify both tokens are different
		require.NotEqual(t, jwtToken, jsonToken)

		// Both should be parseable with their respective secret keys
		parsedJwtClaims, err := jwe_auth.ParseAndDecryptJWE(jwtToken, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedJwtClaims["host"])

		parsedJsonClaims, err := jwe_auth.ParseAndDecryptJWE(jsonToken, jweSecretKey, []byte{})
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedJsonClaims["host"])
	})

	// Test JWT-signed token parsed without JWT secret key
	t.Run("jwt_token_without_jwt_secret", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		// Generate JWT-signed token (with JWT secret key)
		jwtToken, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)

		// Parse with empty JWT secret key - should fall back to JSON parsing and fail
		_, err = jwe_auth.ParseAndDecryptJWE(jwtToken, jweSecretKey, []byte{})
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})

	// Test JSON token parsed with JWT secret key
	t.Run("json_token_with_jwt_secret", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		// Generate JSON-encrypted token (without JWT secret key)
		jsonToken, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, []byte{})
		require.NoError(t, err)

		// Parse with JWT secret key - should fall back to JSON parsing and succeed
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(jsonToken, jweSecretKey, jwtSecretKey)
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedClaims["host"])
	})
}
