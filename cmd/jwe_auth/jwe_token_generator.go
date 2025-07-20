package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"time"

	"github.com/golang-jwt/jwe"
	"github.com/golang-jwt/jwt/v5"
)

// Generate JWE token using CLI flags
func main() {
	var (
		encryptionKey         = flag.String("encryption-key", "your-encryption-key", "Encryption key for JWE token")
		secret                = flag.String("secret", "", "PEM-encoded RSA private key for signing (required)")
		host                  = flag.String("host", "localhost", "ClickHouse host")
		port                  = flag.Int("port", 8123, "ClickHouse port")
		database              = flag.String("database", "default", "ClickHouse database")
		username              = flag.String("username", "default", "ClickHouse username")
		password              = flag.String("password", "", "ClickHouse password")
		protocol              = flag.String("protocol", "http", "ClickHouse protocol (http/tcp)")
		limit                 = flag.Int("limit", 1000, "Default limit for query results")
		expiry                = flag.Int("expiry", 3600, "Token expiry time in seconds")
		tlsEnabled            = flag.Bool("tls", false, "Enable TLS for ClickHouse connection")
		tlsCaCert             = flag.String("tls-ca-cert", "", "Path to CA certificate for ClickHouse connection")
		tlsClientCert         = flag.String("tls-client-cert", "", "Path to client certificate for ClickHouse connection")
		tlsClientKey          = flag.String("tls-client-key", "", "Path to client key for ClickHouse connection")
		tlsInsecureSkipVerify = flag.Bool("tls-insecure-skip-verify", false, "Skip server certificate verification")
	)
	flag.Parse()

	// Create claims for the token
	claims := map[string]interface{}{
		"host":     *host,
		"port":     *port,
		"database": *database,
		"username": *username,
		"protocol": *protocol,
		"exp":      time.Now().Add(time.Duration(*expiry) * time.Second).Unix(),
	}

	// Only include password if provided
	if *password != "" {
		claims["password"] = *password
	}

	// Include limit if provided
	if *limit > 0 {
		claims["limit"] = *limit
	}

	// Include TLS configuration if enabled
	if *tlsEnabled {
		claims["tls_enabled"] = true
		if *tlsCaCert != "" {
			claims["tls_ca_cert"] = *tlsCaCert
		}
		if *tlsClientCert != "" {
			claims["tls_client_cert"] = *tlsClientCert
		}
		if *tlsClientKey != "" {
			claims["tls_client_key"] = *tlsClientKey
		}
		if *tlsInsecureSkipVerify {
			claims["tls_insecure_skip_verify"] = true
		}
	}

	if *secret == "" {
		fmt.Println("Error: --secret flag is required")
		flag.Usage()
		return
	}

	// Parse the provided RSA private key
	block, _ := pem.Decode([]byte(*secret))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Failed to decode PEM block containing private key")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse RSA private key: %v\n", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// 2. Create and sign a JWT with our claims
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims(claims),
	)
	signedJWT, err := token.SignedString(privateKey)
	if err != nil {
		fmt.Printf("Failed to sign JWT: %v\n", err)
		return
	}

	// 3. Encrypt the signed JWT into JWE format
	jweToken, err := jwe.NewJWE(
		jwe.KeyAlgorithmRSAOAEP,
		publicKey,
		jwe.EncryptionTypeA256GCM,
		[]byte(signedJWT),
	)
	if err != nil {
		fmt.Printf("Failed to create JWE: %v\n", err)
		return
	}
	encryptedToken, err := jweToken.CompactSerialize()
	if err != nil {
		fmt.Printf("Failed to serialize JWE: %v\n", err)
		return
	}

	// 4. Print example usage with new encrypted token
	fmt.Println("\nExample usage with SSE transport:")
	fmt.Printf("curl \"http://localhost:8080/sse?token=%s\"\n", encryptedToken)

	fmt.Println("\nExample usage with dynamic path (Go 1.22+):")
	fmt.Printf("curl \"http://localhost:8080/%s/sse\"\n", encryptedToken)

	fmt.Println("JWE Token:")
	fmt.Println(encryptedToken)

}
