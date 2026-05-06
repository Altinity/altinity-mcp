// Package embeddedch boots a ClickHouse server as a host subprocess for tests
// via franchb/embedded-clickhouse. It replaces the testcontainers-based
// fixtures used across this repo, eliminating Docker/Ryuk/proxy plumbing for
// any test that doesn't require Antalya-specific server features.
//
// Stock ClickHouse 26.3 is the default; pass WithFlavor(FlavorAntalya) to run
// the Altinity Antalya binary. On Linux the binary is extracted once from the
// production Docker image into ~/.cache/embedded-clickhouse/. On non-Linux
// hosts (macOS, ...) the binary must be present at that location ahead of
// time — see docs/development_and_testing.md for build/install steps.
package embeddedch

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	embeddedclickhouse "github.com/franchb/embedded-clickhouse"
	"github.com/stretchr/testify/require"
)

// AntalyaImageRef is the Altinity Antalya image used as the source for the
// extracted Antalya ClickHouse binary on Linux. Bump in lockstep with
// production deployments.
const AntalyaImageRef = "altinity/clickhouse-server:26.1.11.20001.altinityantalya"

// Flavor selects which ClickHouse binary embedded-clickhouse runs.
type Flavor int

const (
	// FlavorStock uses the upstream ClickHouse binary that
	// embedded-clickhouse fetches from GitHub releases.
	FlavorStock Flavor = iota
	// FlavorAntalya runs the Altinity Antalya clickhouse binary cached at
	// embeddedClickHouseCacheDir() (typically ~/.cache/embedded-clickhouse/).
	// On Linux the binary is extracted once from AntalyaImageRef on first use.
	// On non-Linux hosts the binary must be built locally and dropped into the
	// cache dir — see docs/development_and_testing.md for instructions.
	FlavorAntalya
)

// Options customizes the ClickHouse fixture spun up by Setup.
type Options struct {
	Flavor        Flavor
	ConfigDropIns []string
	// UsersXML, if non-empty, is written to <DataPath>/users.xml beside the
	// generated config.xml. Use it when a config.d drop-in references
	// `<users_xml><path>users.xml</path></users_xml>` (Antalya's
	// token_processors / user_directories does this) — the file would
	// otherwise not exist and ClickHouse fails startup with CANNOT_LOAD_CONFIG.
	UsersXML string
	// Protocol controls which port (HTTP or TCP) is reflected in the
	// returned ClickHouseConfig. Defaults to HTTP.
	Protocol     config.ClickHouseProtocol
	StartTimeout time.Duration
}

// Option mutates Options.
type Option func(*Options)

// WithFlavor selects the ClickHouse flavor.
func WithFlavor(f Flavor) Option { return func(o *Options) { o.Flavor = f } }

// WithConfigDropIn adds an XML drop-in written to <DataPath>/config.d/N.xml
// before Start. ClickHouse auto-merges these into its main config; this is
// the no-Docker equivalent of testcontainers' Files: []ContainerFile.
func WithConfigDropIn(xml string) Option {
	return func(o *Options) { o.ConfigDropIns = append(o.ConfigDropIns, xml) }
}

// WithTCPProtocol returns the native protocol port instead of HTTP.
func WithTCPProtocol() Option {
	return func(o *Options) { o.Protocol = config.TCPProtocol }
}

// WithStartTimeout overrides the default 60s start timeout.
func WithStartTimeout(d time.Duration) Option {
	return func(o *Options) { o.StartTimeout = d }
}

// WithUsersXML writes the given XML to <DataPath>/users.xml beside config.xml.
// Pair with config.d drop-ins that declare <user_directories><users_xml>.
func WithUsersXML(xml string) Option {
	return func(o *Options) { o.UsersXML = xml }
}

// Setup boots a ClickHouse server as a host subprocess and returns a
// ClickHouseConfig pointing at it. The server is shut down via t.Cleanup.
//
// In short test mode (-short) the test is skipped to avoid the binary
// download cost on quick local iterations.
func Setup(t *testing.T, opts ...Option) *config.ClickHouseConfig {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping embedded ClickHouse in short mode")
	}

	o := Options{
		Protocol:     config.HTTPProtocol,
		StartTimeout: 60 * time.Second,
	}
	for _, fn := range opts {
		fn(&o)
	}

	cfgBuilder := embeddedclickhouse.DefaultConfig().
		Version(embeddedclickhouse.V26_3).
		StartTimeout(o.StartTimeout)

	if o.Flavor == FlavorAntalya {
		bin := EnsureAntalyaBinary(t)
		cfgBuilder = cfgBuilder.BinaryPath(bin)
	} else {
		// embedded-clickhouse v0.4.0's cache layer locks within a process but
		// not across processes. `go test ./...` runs each package as a
		// separate binary, so multiple processes may race to download and
		// extract the same archive into ~/.cache/embedded-clickhouse,
		// corrupting the .tmp file with "write binary: unexpected EOF" or
		// "rename temp file: no such file or directory". Hold an OS-level
		// flock around the first start until the archive lands, then release.
		release, err := acquireFileLock(t, embeddedClickHouseCacheLockPath())
		require.NoError(t, err)
		defer release()
	}

	if len(o.ConfigDropIns) > 0 || o.UsersXML != "" {
		dataDir := t.TempDir()
		if len(o.ConfigDropIns) > 0 {
			configDDir := filepath.Join(dataDir, "config.d")
			require.NoError(t, os.MkdirAll(configDDir, 0o755))
			for i, xml := range o.ConfigDropIns {
				path := filepath.Join(configDDir, "drop-in-"+strconv.Itoa(i)+".xml")
				require.NoError(t, os.WriteFile(path, []byte(xml), 0o644))
			}
		}
		if o.UsersXML != "" {
			require.NoError(t, os.WriteFile(filepath.Join(dataDir, "users.xml"), []byte(o.UsersXML), 0o644))
		}
		cfgBuilder = cfgBuilder.DataPath(dataDir)
	}

	ch := embeddedclickhouse.NewServer(cfgBuilder)
	require.NoError(t, ch.Start(), "embedded-clickhouse start failed")
	t.Cleanup(func() { _ = ch.Stop() })

	addr := ch.HTTPAddr()
	if o.Protocol == config.TCPProtocol {
		addr = ch.TCPAddr()
	}
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	portInt, err := strconv.Atoi(port)
	require.NoError(t, err)

	return &config.ClickHouseConfig{
		Host:             host,
		Port:             portInt,
		Database:         "default",
		Username:         "default",
		Password:         "",
		Protocol:         o.Protocol,
		ReadOnly:         false,
		MaxExecutionTime: 60,
	}
}

// antalyaBinaryCache memoizes the extracted binary path for the lifetime
// of the test process so we only extract once per `go test` invocation.
var (
	antalyaBinaryOnce sync.Once
	antalyaBinaryPath string
	antalyaBinaryErr  error
)

// EnsureAntalyaBinary returns the path to a cached Antalya clickhouse binary
// at embeddedClickHouseCacheDir().
//
// On Linux the binary is extracted once from AntalyaImageRef via Docker.
// On non-Linux hosts the binary must already be present at the expected path
// (Antalya does not publish macOS/Windows Docker images, and a Linux ELF
// cannot run as a host subprocess on macOS). When missing on non-Linux, this
// fails with a message pointing at docs/development_and_testing.md, which
// covers building clickhouse from source on macOS.
func EnsureAntalyaBinary(t *testing.T) string {
	t.Helper()
	antalyaBinaryOnce.Do(func() {
		antalyaBinaryPath, antalyaBinaryErr = ensureAntalyaBinary()
	})
	require.NoError(t, antalyaBinaryErr, "failed to provide Antalya clickhouse binary")
	require.NotEmpty(t, antalyaBinaryPath, "Antalya binary path is empty")
	return antalyaBinaryPath
}

// AntalyaBinaryPath is the on-disk location where EnsureAntalyaBinary looks
// for (and on Linux, caches) the Antalya clickhouse binary.
func AntalyaBinaryPath() string {
	return filepath.Join(embeddedClickHouseCacheDir(), "clickhouse-"+safeFileName(AntalyaImageRef))
}

func ensureAntalyaBinary() (string, error) {
	binPath := AntalyaBinaryPath()
	if st, err := os.Stat(binPath); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
		return binPath, nil
	}
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf(
			"Antalya clickhouse binary not found at %s.\n"+
				"On %s/%s the binary cannot be extracted from the Antalya Docker image (Linux ELF only).\n"+
				"Build clickhouse from source and copy the resulting binary into %s — see docs/development_and_testing.md.",
			binPath, runtime.GOOS, runtime.GOARCH, embeddedClickHouseCacheDir(),
		)
	}
	return extractAntalyaBinaryFromDocker(binPath)
}

// extractAntalyaBinaryFromDocker pulls AntalyaImageRef and copies
// /usr/bin/clickhouse out of a non-running container into binPath. Subsequent
// callers reuse the cached file when the underlying tag hasn't changed.
func extractAntalyaBinaryFromDocker(binPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		return "", err
	}

	if out, err := exec.Command("docker", "pull", AntalyaImageRef).CombinedOutput(); err != nil {
		return "", &extractErr{stage: "docker pull", out: string(out), err: err}
	}

	cname := "antalya-extract-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := exec.Command("docker", "create", "--name", cname, AntalyaImageRef).CombinedOutput(); err != nil {
		return "", &extractErr{stage: "docker create", out: string(out), err: err}
	}
	defer func() {
		_ = exec.Command("docker", "rm", "-f", cname).Run()
	}()

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

// embeddedClickHouseCacheDir is the on-disk cache shared between the Antalya
// extraction path and the cross-process lock used by the stock-CH download
// path. Always ~/.cache/embedded-clickhouse/ — we deliberately avoid
// os.UserCacheDir() because it resolves to ~/Library/Caches on macOS, which
// would split the cache between OSes and surprise developers who built the
// Antalya binary by hand following docs/development_and_testing.md. Falls
// back to /tmp only if $HOME cannot be determined.
func embeddedClickHouseCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/tmp"
	}
	cacheDir := filepath.Join(home, ".cache", "embedded-clickhouse")
	_ = os.MkdirAll(cacheDir, 0o755)
	return cacheDir
}

// embeddedClickHouseCacheLockPath returns the path to a process-private lock
// file used to serialize concurrent first-time stock-CH binary extractions
// when go test runs packages in parallel.
func embeddedClickHouseCacheLockPath() string {
	return filepath.Join(embeddedClickHouseCacheDir(), ".altinity-mcp-extract.lock")
}

// acquireFileLock takes an exclusive flock on the given path, returning a
// release function the caller must defer. Blocks until the lock is granted.
// The lock file is created if it doesn't exist; we never delete it (multiple
// concurrent processes need a stable inode to flock on).
func acquireFileLock(t *testing.T, path string) (func(), error) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
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
