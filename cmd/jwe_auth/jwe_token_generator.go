package main

import (
	"flag"
	"fmt"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"io"
	"os"
	"time"
)

// Generate JWE token using CLI flags
func main() {
	if err := run(os.Stdout, os.Args[1:]); err != nil {
		// The `run` function already prints usage, so just print the error
		if err != flag.ErrHelp {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func run(output io.Writer, args []string) error {
	fs := flag.NewFlagSet("jwe_token_generator", flag.ContinueOnError)
	fs.SetOutput(output)

	var (
		jweSecretKey          = fs.String("jwe-secret-key", "your-jwe-secret-key", "Secret key for JWE token encryption")
		jwtSecretKey          = fs.String("jwt-secret-key", "", "Symmetric secret key for JWT signing (required)")
		host                  = fs.String("host", "localhost", "ClickHouse host")
		port                  = fs.Int("port", 8123, "ClickHouse port")
		database              = fs.String("database", "default", "ClickHouse database")
		username              = fs.String("username", "default", "ClickHouse username")
		password              = fs.String("password", "", "ClickHouse password")
		protocol              = fs.String("protocol", "http", "ClickHouse protocol (http/tcp)")
		limit                 = fs.Int("limit", 1000, "Default limit for query results")
		expiry                = fs.Int("expiry", 3600, "Token expiry time in seconds")
		tlsEnabled            = fs.Bool("tls", false, "Enable TLS for ClickHouse connection")
		tlsCaCert             = fs.String("tls-ca-cert", "", "Path to CA certificate for ClickHouse connection")
		tlsClientCert         = fs.String("tls-client-cert", "", "Path to client certificate for ClickHouse connection")
		tlsClientKey          = fs.String("tls-client-key", "", "Path to client key for ClickHouse connection")
		tlsInsecureSkipVerify = fs.Bool("tls-insecure-skip-verify", false, "Skip server certificate verification")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

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
		fs.Usage()
		return fmt.Errorf("--jwt-secret-key flag is required")
	}

	// 2. Encrypt the signed JWT into JWE format
	encryptedToken, err := jwe_auth.GenerateJWEToken(claims, []byte(*jweSecretKey), []byte(*jwtSecretKey))
	if err != nil {
		return fmt.Errorf("failed to generate JWE token: %w", err)
	}

	// 3. Print example usage with new encrypted token
	_, _ = fmt.Fprintln(output, "\nExample usage with SSE transport:")
	_, _ = fmt.Fprintf(output, "curl \"http://localhost:8080/%s/sse\"\n", encryptedToken)

	_, _ = fmt.Fprintln(output, "JWE Token:")
	_, _ = fmt.Fprintln(output, encryptedToken)

	return nil
}
