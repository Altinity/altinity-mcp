package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func TestJWEAuthEndToEnd(t *testing.T) {
	// This is an integration test that replaces the old test_jwe_auth.sh script.
	// It builds and starts the altinity-mcp server, generates a JWE token,
	// and then makes a request to the server using that token.

	// 1. Build the server binary to a temporary directory
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "altinity-mcp")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./../../cmd/altinity-mcp")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	err := buildCmd.Run()
	require.NoError(t, err, "Failed to build altinity-mcp binary")

	// 2. Find a free port for the server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	err = listener.Close()
	require.NoError(t, err)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// 3. Generate keys
	jwePrivateKey := generateRSAKeys(t)
	jwePrivateKeyPEM := pemEncodePrivateKey(t, jwePrivateKey)
	jwtSecretKey := "test-jwt-super-secret-from-go-test"

	// 4. Start the server as a subprocess
	serverCmd := exec.Command(binaryPath,
		"--transport=sse",
		fmt.Sprintf("--address=%s", "127.0.0.1"),
		fmt.Sprintf("--port=%d", port),
		"--allow-jwe-auth",
		"--jwe-secret-key", jwePrivateKeyPEM,
		"--jwt-secret-key", jwtSecretKey,
		"--log-level=debug",
	)
	// Capture server output for debugging if needed
	var serverOutput bytes.Buffer
	serverCmd.Stdout = &serverOutput
	serverCmd.Stderr = &serverOutput

	err = serverCmd.Start()
	require.NoError(t, err, "Failed to start server process")

	// Ensure server process is killed at the end of the test
	defer func() {
		if err := serverCmd.Process.Kill(); err != nil {
			t.Logf("Failed to kill server process: %v", err)
		}
		// Log server output for diagnosis
		if t.Failed() {
			t.Logf("Server output:\n%s", serverOutput.String())
		}
	}()

	// 5. Wait for the server to be ready by polling the health endpoint
	healthURL := fmt.Sprintf("http://%s/health", serverAddr)
	require.Eventually(t, func() bool {
		resp, err := http.Get(healthURL)
		if err != nil {
			return false
		}
		defer func() { require.NoError(t, resp.Body.Close()) }()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 200*time.Millisecond, "Server did not become healthy in time")

	// 6. Generate the JWE token using the `run` function
	var tokenOutput bytes.Buffer
	tokenGenArgs := []string{
		"--jwe-secret-key", jwePrivateKeyPEM,
		"--jwt-secret-key", jwtSecretKey,
		"--host", "localhost", // these are just dummy claims for the test
	}
	err = run(&tokenOutput, tokenGenArgs)
	require.NoError(t, err, "Token generator failed")

	token := extractTokenFromOutput(tokenOutput.String())
	require.NotEmpty(t, token, "Failed to extract token from generator output: %s", tokenOutput.String())

	// 7. Make a request to the SSE endpoint with the token
	sseURL := fmt.Sprintf("http://%s/%s/sse", serverAddr, token)
	req, err := http.NewRequestWithContext(context.Background(), "GET", sseURL, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")

	// Use a client with a timeout
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "Request to SSE endpoint failed")
	defer func() { require.NoError(t, resp.Body.Close()) }()

	// 8. Check for a successful connection
	require.Equal(t, http.StatusOK, resp.StatusCode, "Expected OK status from SSE endpoint")
	require.Contains(t, resp.Header.Get("Content-Type"), "text/event-stream", "Expected text/event-stream content type")

	// Optionally, read some data from the stream to confirm it's working
	buf := make([]byte, 128)
	readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		<-readCtx.Done()
		if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
			_ = resp.Body.Close()
		}
	}()
	_, err = resp.Body.Read(buf)
	require.NoError(t, err, "Failed to read from SSE stream")
}

func extractTokenFromOutput(output string) string {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if line == "JWE Token:" && i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1])
		}
	}
	return ""
}
