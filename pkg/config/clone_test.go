package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClickHouseConfigClone(t *testing.T) {
	t.Parallel()
	base := ClickHouseConfig{
		Host: "clickhouse.example", ConnectHost: "127.0.0.1", Port: 8123,
		Username: "reader", Password: "fake-password", Protocol: HTTPProtocol,
		TLS: TLSConfig{Enabled: true, CaCert: "fake-ca.pem"}, ReadOnly: true,
		HttpHeaders:   map[string]string{"X-Static": "1"},
		ExtraSettings: map[string]string{"custom_scope": "base"},
		Roles:         []string{"reader"},
	}
	cloned := base.Clone()
	require.Equal(t, base, cloned)
	cloned.HttpHeaders["X-Static"] = "changed"
	cloned.ExtraSettings["custom_scope"] = "changed"
	cloned.Roles[0] = "changed"
	require.Equal(t, "1", base.HttpHeaders["X-Static"])
	require.Equal(t, "base", base.ExtraSettings["custom_scope"])
	require.Equal(t, []string{"reader"}, base.Roles)

	t.Run("nil_fields", func(t *testing.T) {
		cloned := (ClickHouseConfig{}).Clone()
		require.Nil(t, cloned.HttpHeaders)
		require.Nil(t, cloned.ExtraSettings)
		require.Nil(t, cloned.Roles)
	})
	t.Run("empty_fields", func(t *testing.T) {
		cloned := (ClickHouseConfig{HttpHeaders: map[string]string{}, ExtraSettings: map[string]string{}, Roles: []string{}}).Clone()
		require.NotNil(t, cloned.HttpHeaders)
		require.NotNil(t, cloned.ExtraSettings)
		require.NotNil(t, cloned.Roles)
	})
}
