package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// fakeCmd implements Command for tests.
type fakeCmd struct {
	strs    map[string]string
	bools   map[string]bool
	ints    map[string]int
	slices  map[string][]string
	maps    map[string]map[string]string
	wasSet  map[string]bool
}

func (f *fakeCmd) String(name string) string                { return f.strs[name] }
func (f *fakeCmd) Bool(name string) bool                    { return f.bools[name] }
func (f *fakeCmd) Int(name string) int                      { return f.ints[name] }
func (f *fakeCmd) StringSlice(name string) []string         { return f.slices[name] }
func (f *fakeCmd) StringMap(name string) map[string]string  { return f.maps[name] }
func (f *fakeCmd) IsSet(name string) bool                   { return f.wasSet[name] }

func TestBuildFlags_ConfigStruct(t *testing.T) {
	t.Parallel()
	flags := BuildFlags(&Config{})

	byName := map[string]cli.Flag{}
	for _, f := range flags {
		byName[f.Names()[0]] = f
	}

	// Spot-check a representative cross-section across all sub-structs.
	require.Contains(t, byName, "clickhouse-host")
	require.Contains(t, byName, "clickhouse-port")
	require.Contains(t, byName, "clickhouse-tls")
	require.Contains(t, byName, "clickhouse-http-headers")
	require.Contains(t, byName, "transport")
	require.Contains(t, byName, "port")
	require.Contains(t, byName, "server-tls")
	require.Contains(t, byName, "allow-jwe-auth")
	require.Contains(t, byName, "log-level")
	require.Contains(t, byName, "cors-origin")
	require.Contains(t, byName, "tool-input-settings")
	require.Contains(t, byName, "blocked-query-clauses")

	// All OAuth fields should be wired (issue #96).
	require.Contains(t, byName, "oauth-mode")
	require.Contains(t, byName, "oauth-enabled")
	require.Contains(t, byName, "oauth-issuer")
	require.Contains(t, byName, "oauth-jwks-url")
	require.Contains(t, byName, "oauth-audience")
	require.Contains(t, byName, "oauth-client-id")
	require.Contains(t, byName, "oauth-client-secret")
	require.Contains(t, byName, "oauth-gating-secret-key")
	require.Contains(t, byName, "oauth-claims-to-headers")
	require.Contains(t, byName, "oauth-scopes")
	require.Contains(t, byName, "oauth-required-scopes")

	// Type assertions on a sample of each kind.
	require.IsType(t, &cli.StringFlag{}, byName["clickhouse-host"])
	require.IsType(t, &cli.IntFlag{}, byName["clickhouse-port"])
	require.IsType(t, &cli.BoolFlag{}, byName["server-tls"])
	require.IsType(t, &cli.StringSliceFlag{}, byName["oauth-scopes"])
	require.IsType(t, &cli.StringMapFlag{}, byName["clickhouse-http-headers"])
	require.IsType(t, &cli.StringMapFlag{}, byName["oauth-claims-to-headers"])

	// Defaults from `default:` tags are applied where present.
	require.Equal(t, "localhost", byName["clickhouse-host"].(*cli.StringFlag).Value)
	require.Equal(t, 8123, byName["clickhouse-port"].(*cli.IntFlag).Value)
	require.Equal(t, "info", byName["log-level"].(*cli.StringFlag).Value)
	require.Equal(t, "*", byName["cors-origin"].(*cli.StringFlag).Value)
	require.Equal(t, "stdio", byName["transport"].(*cli.StringFlag).Value)

	// At least one OAuth field has no default — empty Value is correct.
	require.Equal(t, "", byName["oauth-gating-secret-key"].(*cli.StringFlag).Value)
}

func TestApplyFlags_SetsValues(t *testing.T) {
	t.Parallel()
	cfg := &Config{}
	cmd := &fakeCmd{
		strs: map[string]string{
			"clickhouse-host":         "ch.internal",
			"oauth-gating-secret-key": "shh",
			"transport":               "http",
			"oauth-mode":              "forward",
		},
		ints:   map[string]int{"clickhouse-port": 9000},
		bools:  map[string]bool{"server-tls": true, "oauth-enabled": true},
		slices: map[string][]string{"oauth-required-scopes": {"openid", "email"}},
		maps:   map[string]map[string]string{"oauth-claims-to-headers": {"sub": "X-User"}},
		wasSet: map[string]bool{
			"clickhouse-host":         true,
			"clickhouse-port":         true,
			"server-tls":              true,
			"oauth-enabled":           true,
			"oauth-gating-secret-key": true,
			"oauth-required-scopes":   true,
			"oauth-claims-to-headers": true,
			"transport":               true,
			"oauth-mode":              true,
		},
	}

	ApplyFlags(cfg, cmd)

	require.Equal(t, "ch.internal", cfg.ClickHouse.Host)
	require.Equal(t, 9000, cfg.ClickHouse.Port)
	require.True(t, cfg.Server.TLS.Enabled)
	require.True(t, cfg.Server.OAuth.Enabled)
	require.Equal(t, "shh", cfg.Server.OAuth.GatingSecretKey)
	require.Equal(t, []string{"openid", "email"}, cfg.Server.OAuth.RequiredScopes)
	require.Equal(t, "X-User", cfg.Server.OAuth.ClaimsToHeaders["sub"])

	// Type-alias conversion: cmd.String returns a plain string, but the
	// struct field is MCPTransport — Convert() handles that.
	require.Equal(t, MCPTransport("http"), cfg.Server.Transport)
	require.Equal(t, "forward", cfg.Server.OAuth.Mode)
}

func TestApplyFlags_DefaultFallback(t *testing.T) {
	t.Parallel()
	cfg := &Config{}                        // all zero values
	cmd := &fakeCmd{wasSet: map[string]bool{}} // nothing set

	ApplyFlags(cfg, cmd)

	// Defaults from `default:` tags fill zero-valued strings/ints.
	require.Equal(t, "localhost", cfg.ClickHouse.Host)
	require.Equal(t, 8123, cfg.ClickHouse.Port)
	require.Equal(t, "default", cfg.ClickHouse.Database)
	require.Equal(t, ClickHouseProtocol("http"), cfg.ClickHouse.Protocol)
	require.Equal(t, MCPTransport("stdio"), cfg.Server.Transport)
	require.Equal(t, 8080, cfg.Server.Port)
	require.Equal(t, "*", cfg.Server.CORSOrigin)
	require.Equal(t, LogLevel("info"), cfg.Logging.Level)

	// Fields without a `default:` tag stay zero.
	require.Equal(t, "", cfg.ClickHouse.Password)
	require.Equal(t, "", cfg.Server.OAuth.GatingSecretKey)
}

func TestApplyFlags_YAMLValuePreservedWhenNotSet(t *testing.T) {
	t.Parallel()
	cfg := &Config{}
	cfg.ClickHouse.Host = "from-yaml.example"
	cfg.Server.OAuth.GatingSecretKey = "from-yaml-secret"
	cmd := &fakeCmd{wasSet: map[string]bool{}}

	ApplyFlags(cfg, cmd)

	require.Equal(t, "from-yaml.example", cfg.ClickHouse.Host)
	require.Equal(t, "from-yaml-secret", cfg.Server.OAuth.GatingSecretKey)
}

func TestApplyFlags_CLIBeatsYAML(t *testing.T) {
	t.Parallel()
	cfg := &Config{}
	cfg.ClickHouse.Host = "from-yaml.example"
	cmd := &fakeCmd{
		strs:   map[string]string{"clickhouse-host": "from-cli.example"},
		wasSet: map[string]bool{"clickhouse-host": true},
	}

	ApplyFlags(cfg, cmd)

	require.Equal(t, "from-cli.example", cfg.ClickHouse.Host)
}

func TestBuildFlags_NoFlagTagSkipped(t *testing.T) {
	t.Parallel()
	type S struct {
		Wired   string `flag:"x" desc:"wired"`
		Skipped string `desc:"no flag tag"`
		Hidden  string `flag:"-" desc:"explicit skip"`
	}
	flags := BuildFlags(&S{})
	require.Len(t, flags, 1)
	require.Equal(t, "x", flags[0].Names()[0])
}
