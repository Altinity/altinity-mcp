package jwe_auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwe"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrMissingToken is returned when JWE token is missing
	ErrMissingToken = errors.New("missing JWE token")
	// ErrInvalidToken is returned when JWE token is invalid
	ErrInvalidToken = errors.New("invalid JWE token")
)

// GenerateJWEToken creates a JWE token by signing a JWT with HS256 and encrypting it with AES Key Wrap (A256KW) and AES-GCM (A256GCM).
func GenerateJWEToken(claims jwt.MapClaims, jweSecretKey []byte, jwtSecretKey []byte) (string, error) {
	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedJWT, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Encrypt JWT to JWE
	jweToken, err := jwe.NewJWE(
		jwe.KeyAlgorithmRSAOAEP,
		jweSecretKey,
		jwe.EncryptionTypeA256GCM,
		[]byte(signedJWT),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE: %w", err)
	}

	compact, err := jweToken.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}
	return compact, nil
}

// ParseAndDecryptJWE parses and validates a JWE token
func ParseAndDecryptJWE(tokenParam string, jweSecretKey []byte, jwtSecretKey []byte) (jwt.MapClaims, error) {
	// 1. Decrypt JWE to get signed JWT payload
	jweToken, err := jwe.ParseEncrypted(tokenParam)
	if err != nil {
		return nil, ErrInvalidToken
	}
	signedJWT, err := jweToken.Decrypt(jweSecretKey)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// 2. Parse and validate inner JWT
	token, err := jwt.Parse(string(signedJWT), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if err := validateClaimsWhitelist(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// validateClaimsWhitelist validates that JWE claims only contain allowed keys
func validateClaimsWhitelist(claims jwt.MapClaims) error {
	// Define whitelist of allowed claim keys
	allowedKeys := map[string]bool{
		// Standard JWT claims
		"iss": true, // issuer
		"sub": true, // subject
		"aud": true, // audience
		"exp": true, // expiration time
		"nbf": true, // not before
		"iat": true, // issued at
		"jti": true, // JWT ID

		// ClickHouse connection claims
		"host":               true,
		"port":               true,
		"database":           true,
		"username":           true,
		"password":           true,
		"protocol":           true,
		"limit":              true,
		"read_only":          true,
		"max_execution_time": true,

		// TLS configuration claims
		"tls_enabled":              true,
		"tls_ca_cert":              true,
		"tls_client_cert":          true,
		"tls_client_key":           true,
		"tls_insecure_skip_verify": true,
	}

	// Check for any disallowed keys
	for key := range claims {
		if !allowedKeys[key] {
			return fmt.Errorf("invalid token claims format: disallowed claim key '%s'", key)
		}
	}

	return nil
}
