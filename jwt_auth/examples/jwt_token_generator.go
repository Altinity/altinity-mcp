package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Generate JWE token using CLI flags
func main() {
	var (
		secretKey             = flag.String("secret", "your-secret-key", "Secret key for signing JWT token")
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
	claims := jwt.MapClaims{
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

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte(*secretKey))
	if err != nil {
		fmt.Printf("Error signing token: %v\n", err)
		return
	}

	// print example command line usage
	fmt.Println("\nExample usage with SSE transport:")
	fmt.Printf("curl \"http://localhost:8080/sse?token=%s\"\n", tokenString)

	fmt.Println("\nExample usage with dynamic path (Go 1.22+):")
	fmt.Printf("curl \"http://localhost:8080/%s/sse\"\n", tokenString)

	fmt.Println("JWT Token:")
	fmt.Println(tokenString)

}
