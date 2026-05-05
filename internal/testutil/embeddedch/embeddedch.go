// Package embeddedch boots a ClickHouse server as a host subprocess for tests
// via franchb/embedded-clickhouse. It replaces the testcontainers-based
// fixtures used across this repo, eliminating Docker/Ryuk/proxy plumbing for
// any test that doesn't require Antalya-specific server features.
//
// Stock ClickHouse 26.3 is the default;
// pass WithFlavor(FlavorAntalya) to extract and run the Altinity Antalya binary from the production Docker image.
// Antalya tests auto-skip on non-Linux hosts because Antalya only
// publishes Linux binaries.
package embeddedch

import (
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
const AntalyaImageRef = "altinity/clickhouse-server:26.1.6.20001.altinityantalya"

// Flavor selects which ClickHouse binary embedded-clickhouse runs.
type Flavor int

const (
	// FlavorStock uses the upstream ClickHouse binary that
	// embedded-clickhouse fetches from GitHub releases.
	FlavorStock Flavor = iota
	// FlavorAntalya pulls the Altinity Antalya Docker image, extracts the
	// clickhouse binary once, and points embedded-clickhouse at it via
	// BinaryPath. Antalya only ships Linux binaries; tests using this
	// flavor are auto-skipped on non-Linux hosts.
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

// EnsureAntalyaBinary returns the path to a cached Antalya clickhouse binary,
// extracting it from the Altinity Docker image on first call.
//
// Skips on non-Linux hosts — Altinity only publishes Antalya as Linux
// binaries in their Docker images, so the Antalya server can't run as a host
// subprocess on macOS or Windows.
func EnsureAntalyaBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("Antalya tests require linux (Antalya publishes Linux binaries only); skipping on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	antalyaBinaryOnce.Do(func() {
		antalyaBinaryPath, antalyaBinaryErr = extractAntalyaBinary()
	})
	require.NoError(t, antalyaBinaryErr, "failed to extract Antalya binary from %s", AntalyaImageRef)
	require.NotEmpty(t, antalyaBinaryPath, "extracted Antalya binary path is empty")
	return antalyaBinaryPath
}

// extractAntalyaBinary pulls AntalyaImageRef and copies /usr/bin/clickhouse
// out of a non-running container into a stable on-disk cache. Subsequent
// callers reuse the cached file when the underlying tag hasn't changed.
func extractAntalyaBinary() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = "/tmp"
	}
	cacheDir = filepath.Join(cacheDir, "altinity-mcp", "antalya-bin")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	binPath := filepath.Join(cacheDir, "clickhouse-"+safeFileName(AntalyaImageRef))
	if st, err := os.Stat(binPath); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
		return binPath, nil
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

// embeddedClickHouseCacheLockPath returns the path to a process-private lock
// file used to serialize concurrent first-time stock-CH binary extractions
// when go test runs packages in parallel.
func embeddedClickHouseCacheLockPath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = "/tmp"
	}
	cacheDir = filepath.Join(cacheDir, "embedded-clickhouse")
	_ = os.MkdirAll(cacheDir, 0o755)
	return filepath.Join(cacheDir, ".altinity-mcp-extract.lock")
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
