package server

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	embeddedclickhouse "github.com/franchb/embedded-clickhouse"
	"github.com/stretchr/testify/require"
)

// antalyaImageRef is the Altinity Antalya image used as the source for the
// extracted Antalya ClickHouse binary on Linux. Bump this in lockstep with
// production.
const antalyaImageRef = "altinity/clickhouse-server:26.1.6.20001.altinityantalya"

// embeddedCHFlavor controls which ClickHouse binary embedded-clickhouse runs.
type embeddedCHFlavor int

const (
	// flavorStock uses the upstream ClickHouse binary that
	// embedded-clickhouse fetches from GitHub releases. Use this for tests
	// that don't depend on Antalya-specific server features
	// (token_processors, dynamic <user_directories><token>, etc.).
	flavorStock embeddedCHFlavor = iota
	// flavorAntalya pulls the Altinity Antalya Docker image, extracts the
	// clickhouse binary once, and points embedded-clickhouse at it via
	// BinaryPath. Antalya only ships Linux binaries, so tests using this
	// flavor are auto-skipped on non-Linux hosts.
	flavorAntalya
)

// embeddedCHOpts customizes the ClickHouse fixture spun up by setupEmbeddedClickHouse.
type embeddedCHOpts struct {
	flavor          embeddedCHFlavor
	configDropIns   []string
	skipDefaultSeed bool
}

// embeddedCHOption mutates embeddedCHOpts.
type embeddedCHOption func(*embeddedCHOpts)

func withFlavor(f embeddedCHFlavor) embeddedCHOption {
	return func(o *embeddedCHOpts) { o.flavor = f }
}

func withConfigDropIn(xml string) embeddedCHOption {
	return func(o *embeddedCHOpts) { o.configDropIns = append(o.configDropIns, xml) }
}

func withoutDefaultTable() embeddedCHOption {
	return func(o *embeddedCHOpts) { o.skipDefaultSeed = true }
}

// setupEmbeddedClickHouse boots a ClickHouse server as a host subprocess via
// embedded-clickhouse and returns a ClickHouseConfig pointing at it.
//
// Default behavior (no opts): stock ClickHouse 26.1, seeded default.test table,
// no config.d drop-ins. Suitable for any test that today uses
// setupClickHouseContainer and doesn't need Antalya-specific features.
//
// Use withFlavor(flavorAntalya) for tests that need token_processors or other
// Altinity Antalya features. Such tests are auto-skipped on non-Linux hosts
// because Antalya doesn't publish darwin/windows binaries.
//
// Use withConfigDropIn(xml) to inject one or more <clickhouse>...</clickhouse>
// XML snippets into the server's config.d/. ClickHouse auto-merges these into
// the main config; this is the no-Docker equivalent of testcontainers'
// Files: []ContainerFile.
func setupEmbeddedClickHouse(t *testing.T, opts ...embeddedCHOption) *config.ClickHouseConfig {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping embedded ClickHouse in short mode")
	}

	var o embeddedCHOpts
	for _, fn := range opts {
		fn(&o)
	}

	cfgBuilder := embeddedclickhouse.DefaultConfig().
		Version(embeddedclickhouse.V26_1).
		StartTimeout(60 * time.Second)

	if o.flavor == flavorAntalya {
		bin := ensureAntalyaBinary(t)
		cfgBuilder = cfgBuilder.BinaryPath(bin)
	}

	if len(o.configDropIns) > 0 {
		// embedded-clickhouse uses os.MkdirTemp("","embedded-clickhouse-*") when
		// DataPath is empty; we need a stable path so we can write drop-ins
		// before Start. t.TempDir cleans up automatically.
		dataDir := t.TempDir()
		configDDir := filepath.Join(dataDir, "config.d")
		require.NoError(t, os.MkdirAll(configDDir, 0o755))
		for i, xml := range o.configDropIns {
			path := filepath.Join(configDDir, "drop-in-"+strconv.Itoa(i)+".xml")
			require.NoError(t, os.WriteFile(path, []byte(xml), 0o644))
		}
		cfgBuilder = cfgBuilder.DataPath(dataDir)
	}

	ch := embeddedclickhouse.NewServer(cfgBuilder)
	require.NoError(t, ch.Start(), "embedded-clickhouse start failed")
	t.Cleanup(func() { _ = ch.Stop() })

	host, port := splitHostPort(t, ch.HTTPAddr())
	chConfig := &config.ClickHouseConfig{
		Host:     host,
		Port:     port,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
	}

	if !o.skipDefaultSeed {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, err := clickhouse.NewClient(ctx, *chConfig)
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })
		_, err = client.ExecuteQuery(ctx, `CREATE TABLE IF NOT EXISTS default.test (
			id UInt64,
			name String,
			created_at DateTime
		) ENGINE = MergeTree() ORDER BY id`)
		require.NoError(t, err)
		_, err = client.ExecuteQuery(ctx, `INSERT INTO default.test VALUES (1, 'test1', now()), (2, 'test2', now())`)
		require.NoError(t, err)
	}

	return chConfig
}

// splitHostPort decomposes "host:port" into the integer port form expected by
// config.ClickHouseConfig.
func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

// portString stringifies an integer port without dragging strconv into many
// callers.
func portString(p int) string { return strconv.Itoa(p) }

// antalyaBinaryCache holds the path to a successfully-extracted Antalya
// binary, computed lazily on first use, then memoized for the rest of the
// process lifetime so we only extract once per `go test ./...` run.
var (
	antalyaBinaryOnce sync.Once
	antalyaBinaryPath string
	antalyaBinaryErr  error
)

// ensureAntalyaBinary returns the path to a cached Antalya clickhouse binary,
// extracting it from the Altinity Docker image on first call.
//
// On non-Linux hosts this calls t.Skip() — Altinity only publishes Antalya as
// Linux binaries in their Docker images, so the Antalya server can't run as
// a host subprocess on macOS or Windows. CI does the heavy lifting on Linux.
func ensureAntalyaBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("Antalya tests require linux (Antalya publishes Linux binaries only); skipping on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	antalyaBinaryOnce.Do(func() {
		antalyaBinaryPath, antalyaBinaryErr = extractAntalyaBinary()
	})
	require.NoError(t, antalyaBinaryErr, "failed to extract Antalya binary from %s", antalyaImageRef)
	require.NotEmpty(t, antalyaBinaryPath, "extracted Antalya binary path is empty")
	return antalyaBinaryPath
}

// extractAntalyaBinary pulls antalyaImageRef and copies /usr/bin/clickhouse out
// of a non-running container, into a stable on-disk cache. Subsequent calls
// reuse the cached file when the underlying image digest hasn't changed.
//
// Cache keying: the binary file path includes the image tag, and the cache is
// invalidated by deleting the file. We don't try to track image digest churn
// — a tag bump in antalyaImageRef triggers a fresh extraction.
func extractAntalyaBinary() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = "/tmp"
	}
	cacheDir = filepath.Join(cacheDir, "altinity-mcp", "antalya-bin")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	tagSafe := safeFileName(antalyaImageRef)
	binPath := filepath.Join(cacheDir, "clickhouse-"+tagSafe)
	if st, err := os.Stat(binPath); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
		return binPath, nil
	}

	// docker pull <image>
	if out, err := exec.Command("docker", "pull", antalyaImageRef).CombinedOutput(); err != nil {
		return "", &extractErr{stage: "docker pull", out: string(out), err: err}
	}

	// docker create --name <unique> <image>
	cname := "antalya-extract-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := exec.Command("docker", "create", "--name", cname, antalyaImageRef).CombinedOutput(); err != nil {
		return "", &extractErr{stage: "docker create", out: string(out), err: err}
	}
	defer func() {
		_ = exec.Command("docker", "rm", "-f", cname).Run()
	}()

	// docker cp <name>:/usr/bin/clickhouse <binPath>
	if out, err := exec.Command("docker", "cp", cname+":/usr/bin/clickhouse", binPath).CombinedOutput(); err != nil {
		return "", &extractErr{stage: "docker cp", out: string(out), err: err}
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		return "", err
	}
	return binPath, nil
}

type extractErr struct {
	stage string
	out   string
	err   error
}

func (e *extractErr) Error() string {
	if e.out != "" {
		return e.stage + ": " + e.err.Error() + "\n" + e.out
	}
	return e.stage + ": " + e.err.Error()
}

func safeFileName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
