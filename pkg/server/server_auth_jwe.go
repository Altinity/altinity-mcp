package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/rs/zerolog/log"
)

// ExtractTokenFromCtx extracts a token from context
func (s *ClickHouseJWEServer) ExtractTokenFromCtx(ctx context.Context) string {
	if tokenFromCtx := ctx.Value(JWETokenKey); tokenFromCtx != nil {
		if tokenStr, ok := tokenFromCtx.(string); ok {
			return tokenStr
		}
	}
	return ""
}

// ExtractTokenFromRequest extracts a token from an HTTP request
func (s *ClickHouseJWEServer) ExtractTokenFromRequest(r *http.Request) string {
	var token string

	// Prefer explicit path token when available to avoid conflicting with OAuth bearer auth.
	if pathToken := r.PathValue("token"); pathToken != "" {
		return pathToken
	}

	// Try Authorization header (Bearer or Basic)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if strings.HasPrefix(authHeader, "Basic ") {
		token = strings.TrimPrefix(authHeader, "Basic ")
	}

	// Try x-altinity-mcp-key header
	if token == "" {
		token = r.Header.Get("x-altinity-mcp-key")
	}

	// Try to extract token from URL path (for OpenAPI compatibility)
	if token == "" {
		pathParts := strings.Split(r.URL.Path, "/")
		for i, part := range pathParts {
			if part == "openapi" && i > 0 {
				token = pathParts[i-1]
				break
			}
		}
	}

	return token
}

func (s *ClickHouseJWEServer) parseJWEClaims(token string) (map[string]interface{}, error) {
	if !s.Config.Server.JWE.Enabled {
		return nil, nil
	}

	if token == "" {
		return nil, jwe_auth.ErrMissingToken
	}

	return jwe_auth.ParseAndDecryptJWE(token, []byte(s.Config.Server.JWE.JWESecretKey), []byte(s.Config.Server.JWE.JWTSecretKey))
}

// ParseJWEClaims parses and decrypts a JWE token into claims.
func (s *ClickHouseJWEServer) ParseJWEClaims(token string) (map[string]interface{}, error) {
	return s.parseJWEClaims(token)
}

// ValidateJWEToken validates a JWE token if JWE auth is enabled
func (s *ClickHouseJWEServer) ValidateJWEToken(token string) error {
	_, err := s.parseJWEClaims(token)
	if err != nil {
		log.Error().Err(err).Msg("JWE token validation failed")
		return err
	}

	return nil
}

// JWEClaimsHaveCredentials returns true if the parsed JWE claims contain a username claim.
func (s *ClickHouseJWEServer) JWEClaimsHaveCredentials(claims map[string]interface{}) bool {
	username, _ := claims["username"].(string)
	return username != ""
}

// JWETokenHasCredentials returns true if the JWE token contains a username claim
func (s *ClickHouseJWEServer) JWETokenHasCredentials(token string) bool {
	claims, err := s.parseJWEClaims(token)
	if err != nil {
		return false
	}
	return s.JWEClaimsHaveCredentials(claims)
}
