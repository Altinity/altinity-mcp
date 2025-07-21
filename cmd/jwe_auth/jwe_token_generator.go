package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Generate JWE token using CLI flags
func main() {
	var (
		jweSecretKey          = flag.String("jwe-secret-key", "your-jwe-secret-key", "PEM-encoded RSA private key for JWE encryption")
		jwtSecretKey          = flag.String("jwt-secret-key", "", "Symmetric secret key for JWT signing (required)")
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

	if *jwtSecretKey == "" {
		fmt.Println("Error: --jwt-secret-key flag is required")
		flag.Usage()
		return
	}
	// 2. Parse the provided RSA private key for JWE
	block, _ := pem.Decode([]byte(*jweSecretKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Failed to decode PEM containing private key")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse RSA private key: %v\n", err)
		return
	}

	// 3. Encrypt the signed JWT into JWE format
	encryptedToken, err := jwe_auth.GenerateJWEToken(claims, &privateKey.PublicKey, []byte(*jwtSecretKey))
	if err != nil {
		fmt.Printf("Failed to generate JWE token: %v\n", err)
		return
	}

	// 4. Print example usage with new encrypted token
	fmt.Println("\nExample usage with SSE transport:")
	fmt.Printf("curl \"http://localhost:8080/%s/sse\"\n", encryptedToken)

	fmt.Println("JWE Token:")
	fmt.Println(encryptedToken)

}
