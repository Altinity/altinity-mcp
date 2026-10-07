package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJWETLSMaterialPath(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "allowed")
	require.NoError(t, os.Mkdir(root, 0700))
	allowed := filepath.Join(root, "ca.pem")
	require.NoError(t, os.WriteFile(allowed, []byte("fake certificate"), 0600))
	outside := filepath.Join(parent, "outside.pem")
	require.NoError(t, os.WriteFile(outside, []byte("private-outside-content"), 0600))
	sibling := filepath.Join(parent, "allowed-sibling")
	require.NoError(t, os.Mkdir(sibling, 0700))
	siblingFile := filepath.Join(sibling, "ca.pem")
	require.NoError(t, os.WriteFile(siblingFile, []byte("private-sibling-content"), 0600))
	escape := filepath.Join(root, "escape.pem")
	require.NoError(t, os.Symlink(outside, escape))
	escapeDir := filepath.Join(root, "escape-dir")
	require.NoError(t, os.Symlink(sibling, escapeDir))
	insideLink := filepath.Join(root, "inside.pem")
	require.NoError(t, os.Symlink(allowed, insideLink))
	cfg := JWEConfig{TLSMaterialDir: root}
	for name, path := range map[string]string{
		"absolute_outside": outside, "sibling_prefix": siblingFile,
		"traversal": root + "/../outside.pem", "internal_traversal": root + "/sub/../ca.pem",
		"relative": "ca.pem", "symlink_file_escape": escape,
		"symlink_directory_escape": filepath.Join(escapeDir, "ca.pem"),
		"missing":                  filepath.Join(root, "missing.pem"), "directory_itself": root,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cfg.ValidateTLSMaterialPath(path)
			require.EqualError(t, err, "jwe: invalid TLS material path")
		})
	}
	for _, path := range []string{allowed, insideLink} {
		resolved, err := cfg.ValidateTLSMaterialPath(path)
		require.NoError(t, err)
		require.Equal(t, allowed, resolved)
	}
	_, err := (JWEConfig{}).ValidateTLSMaterialPath(allowed)
	require.EqualError(t, err, "jwe: invalid TLS material path")
	resolved, err := (JWEConfig{}).ValidateTLSMaterialPath("")
	require.NoError(t, err)
	require.Empty(t, resolved)
}
