package jwe_auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	// ErrMissingToken is returned when JWE token is missing
	ErrMissingToken = errors.New("missing JWE token")
	// ErrInvalidToken is returned when JWE token is invalid
	ErrInvalidToken = errors.New("invalid JWE token")
)

// hashToKey converts any string to a 32-byte key using SHA256 hash
func hashToKey(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

// GenerateJWEToken creates a JWE token by signing a JWT with HS256 and encrypting it with AES Key Wrap (A256KW) and AES-GCM (A256GCM).
func GenerateJWEToken(claims map[string]interface{}, jweSecretKey []byte, jwtSecretKey []byte) (string, error) {
	// Hash the keys to ensure they are 32 bytes
	hashedJWTKey := hashToKey(jwtSecretKey)
	hashedJWEKey := hashToKey(jweSecretKey)

	// 1. Create a new signer from the JWT secret key
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hashedJWTKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signer: %w", err)
	}

	// 2. Sign the claims to create a JWT
	builder := jwt.Signed(signer).Claims(claims)
	signedJWT, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// 3. Create an encrypter from the JWE secret key
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256KW, Key: hashedJWEKey},
		(&jose.EncrypterOptions{}).WithType("JWE").WithContentType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE encrypter: %w", err)
	}

	// 4. Encrypt the signed JWT
	jweObject, err := encrypter.Encrypt([]byte(signedJWT))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt JWE: %w", err)
	}

	// 5. Serialize the JWE to compact form
	return jweObject.CompactSerialize()
}

// ParseAndDecryptJWE parses and validates a JWE token
func ParseAndDecryptJWE(tokenParam string, jweSecretKey []byte, jwtSecretKey []byte) (map[string]interface{}, error) {
	// Hash the keys to ensure they are 32 bytes
	hashedJWTKey := hashToKey(jwtSecretKey)
	hashedJWEKey := hashToKey(jweSecretKey)

	// 1. Parse the JWE token
	jweObject, err := jose.ParseEncrypted(tokenParam, []jose.KeyAlgorithm{jose.A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, ErrInvalidToken
	}

	// 2. Decrypt the JWE token
	decrypted, err := jweObject.Decrypt(hashedJWEKey)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// 3. Parse the inner JWT
	nestedToken, err := jwt.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return nil, ErrInvalidToken
	}

	// 4. Verify the signature and get the claims
	claims := make(map[string]interface{})
	if err := nestedToken.Claims(hashedJWTKey, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	// 5. Validate claims
	if err := validateClaimsWhitelist(claims); err != nil {
		return nil, err
	}

	// 6. Validate expiration
	if err := validateExpiration(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// validateClaimsWhitelist validates that JWE claims only contain allowed keys
func validateClaimsWhitelist(claims map[string]interface{}) error {
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

// validateExpiration checks if the token has expired
func validateExpiration(claims map[string]interface{}) error {
	if exp, ok := claims["exp"]; ok {
		var expTime int64
		switch v := exp.(type) {
		case float64:
			expTime = int64(v)
		case int64:
			expTime = v
		case int:
			expTime = int64(v)
		default:
			return ErrInvalidToken
		}
		
		if time.Now().Unix() > expTime {
			return ErrInvalidToken
		}
	}
	return nil
}
