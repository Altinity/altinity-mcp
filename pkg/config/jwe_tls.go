package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidateTLSMaterialPath validates a token-selected file without reading its
// contents. Nonempty paths must be absolute and contained in TLSMaterialDir,
// both lexically and after resolving symlinks. The directory and its files must
// be operator-controlled and must not be writable by token holders.
// Errors deliberately omit filesystem paths and underlying filesystem errors.
func (c JWEConfig) ValidateTLSMaterialPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	invalid := fmt.Errorf("jwe: invalid TLS material path")
	if c.TLSMaterialDir == "" || !filepath.IsAbs(path) {
		return "", invalid
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return "", invalid
		}
	}
	root, err := filepath.Abs(c.TLSMaterialDir)
	if err != nil || !pathWithin(root, path) {
		return "", invalid
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", invalid
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil || !pathWithin(resolvedRoot, resolvedPath) {
		return "", invalid
	}
	return resolvedPath, nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
