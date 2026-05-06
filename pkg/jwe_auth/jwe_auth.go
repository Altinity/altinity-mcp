package jwe_auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/hkdf"
)

var (
	// ErrMissingToken is returned when JWE token is missing
	ErrMissingToken = errors.New("missing JWE token")
	// ErrInvalidToken is returned when JWE token is invalid
	ErrInvalidToken = errors.New("invalid JWE token")
)

// HashSHA256 converts any string to a 32-byte key using SHA256 hash.
//
// Deprecated for new contexts: SHA-256 of a shared secret produces ONE key
// that has to serve every cryptographic use of that secret. A leak of any
// downstream artifact (a single decrypted JWE, an oracle on the HS256 MAC,
// etc.) targets the same key that protects every other use. Prefer
// DeriveKey(secret, "<context-namespace>/v<n>") for new code so each use
// gets an independent key via HKDF-SHA256 (RFC 5869 §3.2 domain separation).
//
// HashSHA256 is retained because some artifacts in the wild were minted
// against this derivation; rotating to HKDF requires accepting both during
// the rotation window.
func HashSHA256(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

// DeriveKey returns 32 bytes derived from the secret via HKDF-SHA256 with
// the given info label (RFC 5869). Different info labels produce
// independent keys, so a single shared secret can safely back multiple
// cryptographic uses without one context's exposure compromising others.
//
// `info` is application-defined; conventionally namespaced per use, e.g.
// "altinity-mcp/oauth/client-id/v1". The /vN suffix lets you rotate a
// specific key without changing the unrelated ones.
func DeriveKey(secret []byte, info string) []byte {
	h := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, 32)
	_, _ = io.ReadFull(h, out) // hkdf.Reader never errors before requested bytes
	return out
}

// ValidateClaimsWhitelist exposes the JWE claim-key whitelist used by
// ParseAndDecryptJWE so callers that decrypt JWE artifacts via a different
// key-derivation path (e.g. HKDF) can apply the same security invariant.
func ValidateClaimsWhitelist(claims map[string]interface{}) error {
	return validateClaimsWhitelist(claims)
}

// ValidateExpiration exposes the JWE expiration check used by
// ParseAndDecryptJWE for the same reason as ValidateClaimsWhitelist above.
func ValidateExpiration(claims map[string]interface{}) error {
	return validateExpiration(claims)
}

// GenerateJWEToken creates a JWE token by either:
// 1. Signing a JWT with HS256 and encrypting it (when jwtSecretKey is provided), or
// 2. Serializing claims to JSON and encrypting that (when jwtSecretKey is empty)
func GenerateJWEToken(claims map[string]interface{}, jweSecretKey []byte, jwtSecretKey []byte) (string, error) {
	// Hash the JWE key to ensure it is 32 bytes
	hashedJWEKey := HashSHA256(jweSecretKey)

	var plaintext []byte
	var contentType string

	if len(jwtSecretKey) > 0 {
		// JWT signing is enabled - sign the claims first
		hashedJWTKey := HashSHA256(jwtSecretKey)

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

		plaintext = []byte(signedJWT)
		contentType = "JWT"
	} else {
		// No JWT signing - serialize claims directly to JSON
		jsonData, err := json.Marshal(claims)
		if err != nil {
			return "", fmt.Errorf("failed to marshal claims to JSON: %w", err)
		}

		plaintext = jsonData
		contentType = "JSON"
	}

	// 3. Create an encrypter from the JWE secret key
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256KW, Key: hashedJWEKey},
		(&jose.EncrypterOptions{}).WithType("JWE").WithContentType(jose.ContentType(contentType)),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE encrypter: %w", err)
	}

	// 4. Encrypt the plaintext (signed JWT or JSON)
	jweObject, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt JWE: %w", err)
	}

	// 5. Serialize the JWE to compact form
	return jweObject.CompactSerialize()
}

// ParseAndDecryptJWE parses and validates a JWE token
func ParseAndDecryptJWE(encryptedToken string, jweSecretKey []byte, jwtSecretKey []byte) (map[string]interface{}, error) {
	// Hash the JWE key to ensure it is 32 bytes
	hashedJWEKey := HashSHA256(jweSecretKey)

	// 1. Parse the JWE token
	jweObject, err := jose.ParseEncrypted(encryptedToken, []jose.KeyAlgorithm{jose.A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, ErrInvalidToken
	}

	// 2. Decrypt the JWE token
	decrypted, err := jweObject.Decrypt(hashedJWEKey)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Get the content type to determine how to process the decrypted data
	contentType := "JWT" // default for backward compatibility
	if hdr, ok := jweObject.Header.ExtraHeaders[jose.HeaderContentType]; ok {
		if ct, ok := hdr.(string); ok {
			contentType = ct
		}
	}

	var claims map[string]interface{}

	switch contentType {
	case "JWT":
		// Try to parse as JWT if JWT secret key is provided
		if len(jwtSecretKey) > 0 {
			hashedJWTKey := HashSHA256(jwtSecretKey)

			// 3. Parse the inner JWT
			nestedToken, err := jwt.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.HS256})
			if err != nil {
				return nil, ErrInvalidToken
			}

			// 4. Verify the signature and get the claims
			claims = make(map[string]interface{})
			if err := nestedToken.Claims(hashedJWTKey, &claims); err != nil {
				return nil, ErrInvalidToken
			}
		} else {
			// If no JWT secret key, treat as JSON
			if err := json.Unmarshal(decrypted, &claims); err != nil {
				return nil, ErrInvalidToken
			}
		}
	case "JSON":
		// Parse directly as JSON
		if err := json.Unmarshal(decrypted, &claims); err != nil {
			return nil, ErrInvalidToken
		}
	default:
		// Try JWT first, then fall back to JSON
		if len(jwtSecretKey) > 0 {
			hashedJWTKey := HashSHA256(jwtSecretKey)

			// Try to parse as JWT
			nestedToken, err := jwt.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.HS256})
			if err != nil {
				// Fall back to JSON parsing
				if err := json.Unmarshal(decrypted, &claims); err != nil {
					return nil, ErrInvalidToken
				}
			} else {
				// Successfully parsed as JWT, verify signature
				claims = make(map[string]interface{})
				if err := nestedToken.Claims(hashedJWTKey, &claims); err != nil {
					return nil, ErrInvalidToken
				}
			}
		} else {
			// No JWT secret key, parse as JSON
			if err := json.Unmarshal(decrypted, &claims); err != nil {
				return nil, ErrInvalidToken
			}
		}
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

		// OAuth gating/client registration claims
		"grant_type":                 true,
		"redirect_uris":              true,
		"token_endpoint_auth_method": true,
		"client_id":                  true,
		"client_secret":              true,
		"client_name":                true,
		"redirect_uri":               true,
		"scope":                      true,
		"client_state":               true,
		"code_challenge":             true,
		"code_challenge_method":      true,
		"upstream_bearer_token":      true,
		"upstream_refresh_token":     true,
		"upstream_token_type":        true,
		"access_token_exp":           true,
		"email":                      true,
		"name":                       true,
		"hd":                         true,
		"email_verified":             true,
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
