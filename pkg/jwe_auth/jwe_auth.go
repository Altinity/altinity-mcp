package jwe_auth

import (
	"fmt"
	"github.com/golang-jwt/jwe"
	"github.com/golang-jwt/jwt/v5"
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
		jwe.KeyAlgorithmA256KW,
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
