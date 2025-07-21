package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// Helper functions for generating and encoding RSA keys for tests
func generateRSAKeys(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey
}

func pemEncodePrivateKey(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func TestRunGenerator(t *testing.T) {
	privateKey := generateRSAKeys(t)
	privateKeyPEM := pemEncodePrivateKey(t, privateKey)

	testCases := []struct {
		name             string
		args             []string
		expectedError    string
		expectedInOutput string
	}{
		{
			name: "successful_generation",
			args: []string{
				"--jwe-secret-key", privateKeyPEM,
				"--jwt-secret-key", "test-jwt-secret",
				"--host", "testhost",
				"--port", "9000",
				"--database", "testdb",
				"--username", "testuser",
				"--password", "testpass",
				"--protocol", "tcp",
				"--limit", "500",
				"--expiry", "60",
				"--tls",
				"--tls-ca-cert", "ca.crt",
				"--tls-client-cert", "client.crt",
				"--tls-client-key", "client.key",
				"--tls-insecure-skip-verify",
			},
			expectedInOutput: "JWE Token:",
		},
		{
			name: "missing_jwt_secret_key",
			args: []string{
				"--jwe-secret-key", privateKeyPEM,
			},
			expectedError:    "--jwt-secret-key flag is required",
			expectedInOutput: "Usage of jwe_token_generator:",
		},
		{
			name: "invalid_jwe_key_not_pem",
			args: []string{
				"--jwe-secret-key", "not-a-pem-key",
				"--jwt-secret-key", "test-jwt-secret",
			},
			expectedError: "failed to decode PEM block from jwe-secret-key",
		},
		{
			name: "invalid_jwe_key_wrong_type",
			args: []string{
				"--jwe-secret-key", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy")})),
				"--jwt-secret-key", "test-jwt-secret",
			},
			expectedError: "jwe-secret-key is not of type RSA PRIVATE KEY",
		},
		{
			name: "invalid_jwe_key_not_rsa",
			args: []string{
				"--jwe-secret-key", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("invalid bytes")})),
				"--jwt-secret-key", "test-jwt-secret",
			},
			expectedError: "failed to parse RSA private key",
		},
		{
			name:             "help_flag",
			args:             []string{"-h"},
			expectedError:    "flag: help requested",
			expectedInOutput: "Usage of jwe_token_generator:",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(&out, tc.args)

			if tc.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
			}

			if tc.expectedInOutput != "" {
				require.Contains(t, out.String(), tc.expectedInOutput)
			}
		})
	}
}
