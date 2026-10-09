# Third-Party License Attribution

This file lists third-party Go dependencies used by the
`altinity-mcp` and `jwe_auth` binaries, with their
SPDX license identifiers.

Generated with [`licenseclassifier`](https://github.com/google/licenseclassifier)
(same engine used by [`go-licenses`](https://github.com/google/go-licenses)):

```bash
go list -deps -f '{{if not .Standard}}{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}' \
  ./cmd/altinity-mcp ./cmd/jwe_auth
```

The machine-readable companion CSV is [`THIRD_PARTY_LICENSES.csv`](THIRD_PARTY_LICENSES.csv)
(`Module`, `License file`, `Licenses`).

License texts are available via the URLs in the **License file** column
(or in the local Go module cache).
See the repository root for the main project license.

## Summary

| License | Packages |
|---------|----------|
| BSD-3-Clause | 13 |
| MIT | 13 |
| Apache-2.0 | 7 |
| Apache-2.0, BSD-3-Clause | 2 |
| Apache-2.0, MIT | 2 |
| Apache-2.0, BSD-3-Clause, MIT | 1 |
| MIT-0 | 1 |

**Total packages:** 39

## Packages

| Package | License | License file |
|---------|---------|--------------|
| `github.com/AfterShip/clickhouse-sql-parser` | MIT | [`LICENSE`](https://github.com/AfterShip/clickhouse-sql-parser/blob/v0.5.6/LICENSE) |
| `github.com/altinity/go-mcp-oauth-sdk` | Apache-2.0 | [`LICENSE`](https://github.com/altinity/go-mcp-oauth-sdk/blob/v0.2.1/LICENSE) |
| `github.com/andybalholm/brotli` | MIT | [`LICENSE`](https://github.com/andybalholm/brotli/blob/v1.2.2/LICENSE) |
| `github.com/beorn7/perks` | MIT | [`LICENSE`](https://github.com/beorn7/perks/blob/v1.0.1/LICENSE) |
| `github.com/cespare/xxhash/v2` | MIT | [`LICENSE.txt`](https://github.com/cespare/xxhash/blob/v2.3.0/LICENSE.txt) |
| `github.com/ClickHouse/ch-go` | Apache-2.0 | [`LICENSE`](https://github.com/ClickHouse/ch-go/blob/v0.74.0/LICENSE) |
| `github.com/ClickHouse/clickhouse-go/v2` | Apache-2.0 | [`LICENSE`](https://github.com/ClickHouse/clickhouse-go/blob/v2.48.0/LICENSE) |
| `github.com/go-faster/city` | MIT | [`LICENSE`](https://github.com/go-faster/city/blob/v1.0.1/LICENSE) |
| `github.com/go-faster/errors` | BSD-3-Clause | [`LICENSE`](https://github.com/go-faster/errors/blob/v0.8.0/LICENSE) |
| `github.com/go-jose/go-jose/v4` | Apache-2.0 | [`LICENSE`](https://github.com/go-jose/go-jose/blob/v4.1.5/LICENSE) |
| `github.com/google/jsonschema-go` | MIT | [`LICENSE`](https://github.com/google/jsonschema-go/blob/v0.4.3/LICENSE) |
| `github.com/google/uuid` | BSD-3-Clause | [`LICENSE`](https://github.com/google/uuid/blob/v1.6.0/LICENSE) |
| `github.com/klauspost/compress` | Apache-2.0, BSD-3-Clause, MIT | [`LICENSE`](https://github.com/klauspost/compress/blob/v1.19.1/LICENSE) |
| `github.com/mattn/go-colorable` | MIT | [`LICENSE`](https://github.com/mattn/go-colorable/blob/v0.1.15/LICENSE) |
| `github.com/mattn/go-isatty` | MIT | [`LICENSE`](https://github.com/mattn/go-isatty/blob/v0.0.24/LICENSE) |
| `github.com/modelcontextprotocol/go-sdk` | Apache-2.0, MIT | [`LICENSE`](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/LICENSE) |
| `github.com/munnerz/goautoneg` | BSD-3-Clause | [`LICENSE`](https://github.com/munnerz/goautoneg/blob/v0.0.0-20191010083416-a7dc8b61c822/LICENSE) |
| `github.com/paulmach/orb` | MIT | [`LICENSE.md`](https://github.com/paulmach/orb/blob/v0.13.0/LICENSE.md) |
| `github.com/pierrec/lz4/v4` | BSD-3-Clause | [`LICENSE`](https://github.com/pierrec/lz4/blob/v4.1.27/LICENSE) |
| `github.com/prometheus/client_golang` | Apache-2.0 | [`LICENSE`](https://github.com/prometheus/client_golang/blob/v1.24.1/LICENSE) |
| `github.com/prometheus/client_model` | Apache-2.0 | [`LICENSE`](https://github.com/prometheus/client_model/blob/v0.6.3/LICENSE) |
| `github.com/prometheus/common` | Apache-2.0 | [`LICENSE`](https://github.com/prometheus/common/blob/v0.70.1/LICENSE) |
| `github.com/rs/zerolog` | MIT | [`LICENSE`](https://github.com/rs/zerolog/blob/v1.35.1/LICENSE) |
| `github.com/segmentio/asm` | MIT-0 | [`LICENSE`](https://github.com/segmentio/asm/blob/v1.2.1/LICENSE) |
| `github.com/segmentio/encoding` | MIT | [`LICENSE`](https://github.com/segmentio/encoding/blob/v0.5.4/LICENSE) |
| `github.com/shopspring/decimal` | MIT | [`LICENSE`](https://github.com/shopspring/decimal/blob/v1.4.0/LICENSE) |
| `github.com/urfave/cli/v3` | MIT | [`LICENSE`](https://github.com/urfave/cli/blob/v3.14.0/LICENSE) |
| `github.com/yosida95/uritemplate/v3` | BSD-3-Clause | [`LICENSE`](https://github.com/yosida95/uritemplate/blob/v3.0.2/LICENSE) |
| `go.opentelemetry.io/otel` | Apache-2.0, BSD-3-Clause | [`LICENSE`](https://github.com/open-telemetry/opentelemetry-go/blob/v1.44.0/LICENSE) |
| `go.opentelemetry.io/otel/trace` | Apache-2.0, BSD-3-Clause | [`LICENSE`](https://github.com/open-telemetry/opentelemetry-go/blob/v1.44.0/LICENSE) |
| `golang.org/x/crypto` | BSD-3-Clause | [`LICENSE`](https://github.com/golang/crypto/blob/v0.57.0/LICENSE) |
| `golang.org/x/net` | BSD-3-Clause | [`LICENSE`](https://github.com/golang/net/blob/v0.59.0/LICENSE) |
| `golang.org/x/oauth2` | BSD-3-Clause | [`LICENSE`](https://github.com/golang/oauth2/blob/v0.36.0/LICENSE) |
| `golang.org/x/sync` | BSD-3-Clause | [`LICENSE`](https://github.com/golang/sync/blob/v0.23.0/LICENSE) |
| `golang.org/x/sys` | BSD-3-Clause | [`LICENSE`](https://github.com/golang/sys/blob/v0.48.0/LICENSE) |
| `golang.org/x/text` | BSD-3-Clause | [`LICENSE`](https://github.com/golang/text/blob/v0.42.0/LICENSE) |
| `golang.org/x/time` | BSD-3-Clause | [`LICENSE`](https://github.com/golang/time/blob/v0.15.0/LICENSE) |
| `google.golang.org/protobuf` | BSD-3-Clause | [`LICENSE`](https://github.com/protocolbuffers/protobuf-go/blob/v1.36.12/LICENSE) |
| `gopkg.in/yaml.v3` | Apache-2.0, MIT | [`LICENSE`](https://github.com/go-yaml/yaml/blob/v3.0.1/LICENSE) |
