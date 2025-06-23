package main

import (
	"flag"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func main() {
	var (
		secretKey = flag.String("secret", "your-secret-key", "Secret key for signing JWT token")
		host      = flag.String("host", "localhost", "ClickHouse host")
		port      = flag.Int("port", 8123, "ClickHouse port")
		database  = flag.String("database", "default", "ClickHouse database")
		username  = flag.String("username", "default", "ClickHouse username")
		password  = flag.String("password", "", "ClickHouse password")
		protocol  = flag.String("protocol", "http", "ClickHouse protocol (http/tcp)")
		expiry    = flag.Int("expiry", 3600, "Token expiry time in seconds")
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

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte(*secretKey))
	if err != nil {
		fmt.Printf("Error signing token: %v\n", err)
		return
	}

	fmt.Println("JWT Token:")
	fmt.Println(tokenString)

	// Also print example command line usage
	fmt.Println("\nExample usage with SSE transport:")
	fmt.Printf("curl \"http://localhost:8080/sse?token=%s\"\n", tokenString)

	fmt.Println("\nExample usage with dynamic path (Go 1.22+):")
	fmt.Printf("curl \"http://localhost:8080/%s/sse\"\n", tokenString)
}
