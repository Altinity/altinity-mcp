# Development and Testing

This document collects the local development workflow and the repository's test entry points in one place.

## Prerequisites

- Go 1.26 or later
- Docker, for integration tests (including OAuth e2e tests)
- A local or reachable ClickHouse server, if you want to run `test-connection` manually

## Build

Build the main binary:

```bash
go build -o altinity-mcp ./cmd/altinity-mcp
```

Check the current build:

```bash
./altinity-mcp version
```

## Quick Local Check

Validate that the binary can reach ClickHouse before running broader tests:

```bash
./altinity-mcp test-connection \
  --clickhouse-host localhost \
  --clickhouse-port 8123 \
  --clickhouse-database default
```

## Test Matrix

### Full Default Suite

Run the default repository test suite:

```bash
go test ./...
```

This is the baseline command for day-to-day work. It runs unit tests plus the Docker-backed integration tests that are enabled by default in the repository.

### Package-Focused Runs

Run package tests only:

```bash
go test ./pkg/...
```

Run CLI and HTTP handler tests:

```bash
go test -v ./cmd/altinity-mcp/...
```

Run OAuth-focused tests only:

```bash
go test ./pkg/server ./cmd/altinity-mcp ./pkg/config -run OAuth -count=1 -v
```

## Docker-Backed Integration Tests

Several tests start temporary ClickHouse containers with `testcontainers-go`. Before running them, make sure Docker is running and the current user can access the Docker socket.

If Docker is unavailable, the default suite will not be reliable.

## OAuth End-to-End Tests

OAuth e2e tests validate bearer-token forwarding through MCP to ClickHouse. They use a lightweight in-process mock OIDC provider and an `altinity/clickhouse-server:25.8.16.20001.altinityantalya` container (required for `token_processors` support — standard ClickHouse images do not include it).

These tests run automatically as part of `go test ./...` (skipped with `-short`).

For configuration background and provider-specific setup, see [oauth_authorization.md](./oauth_authorization.md).

## Embedded ClickHouse for Tests

Tests under `internal/testutil/embeddedch` boot ClickHouse as a host subprocess instead of a container. Two flavors are supported:

- **Stock** — upstream ClickHouse, downloaded automatically by `franchb/embedded-clickhouse`.
- **Antalya** — the Altinity Antalya binary, expected at `~/.cache/embedded-clickhouse/clickhouse-<sanitized-image-tag>`.

On Linux the Antalya binary is extracted once from the Antalya Docker image (`altinity/clickhouse-server:26.1.6.20001.altinityantalya`) on first use. 
On macOS and other non-Linux hosts you must build it from source ahead of time — the Antalya Docker image only ships a Linux ELF, so it cannot run as a host subprocess on macOS.

### Build the Antalya `clickhouse` binary on macOS

The Antalya tree shares the upstream ClickHouse build system, so the standard macOS build flow applies. Steps below are tailored for `~/.cache/embedded-clickhouse/` placement expected by the tests in this repo.

1. Install build prerequisites via Homebrew:

   ```bash
   brew update
   brew install ccache cmake ninja libtool gettext llvm lld binutils grep findutils nasm bash rust rustup
   ```

2. Extract the Antalya image ref/tag straight from the Go source so the build stays in lockstep with what the tests expect. Run this from the root of the `altinity-mcp` checkout:

   ```bash
   # AntalyaImageRef looks like "altinity/clickhouse-server:26.1.6.20001.altinityantalya"
   ANTALYA_IMAGE_REF=$(grep -E '^\s*const AntalyaImageRef' internal/testutil/embeddedch/embeddedch.go | sed -E 's/.*"([^"]+)".*/\1/')
   # 26.1.6.20001.altinityantalya
   ANTALYA_IMAGE_TAG="v${ANTALYA_IMAGE_REF##*:}"   
   echo "image=$ANTALYA_IMAGE_REF tag=$ANTALYA_IMAGE_TAG"
   ```

   Keep this shell session open — `ANTALYA_IMAGE_REF` and `ANTALYA_IMAGE_TAG` are reused in steps 3 and 5.

3. Clone the Altinity ClickHouse fork (Antalya branches/tags live here) with submodules and check out the tag matching `ANTALYA_IMAGE_TAG`. The clone path **must not contain whitespace**:

   ```bash
   git clone https://github.com/Altinity/ClickHouse.git ~/src/github.com/altinity/ClickHouse
   cd ~/src/github.com/altinity/ClickHouse
   git fetch --tags
   git checkout "$ANTALYA_IMAGE_TAG"
   git submodule update --init --jobs 8
   ```

   If you skipped `--recurse-submodules` during clone, the explicit `git submodule update --init` step is required — submodules are not checked out by default.

4. Install the Rust nightly toolchain ClickHouse pins. The version is hardcoded in `contrib/corrosion-cmake/CMakeLists.txt` (`Rust_TOOLCHAIN`); if you skip this step `cmake` fails with `Cannot find nightly-YYYY-MM-DD Rust toolchain`. Extract it from the source so you always install exactly what the build expects:

   ```bash
   cd ~/src/github.com/altinity/ClickHouse
   # First time only: initialise rustup if you installed it via Homebrew.
   # `brew install rustup` puts the binary on PATH but does not pick a default
   # toolchain — running rustup-init -y is the supported one-shot setup.
   command -v rustup-init >/dev/null && rustup-init -y --no-modify-path --default-toolchain stable

   RUST_TOOLCHAIN=$(grep -E 'set\(Rust_TOOLCHAIN' contrib/corrosion-cmake/CMakeLists.txt | sed -E 's/.*"([^"]+)".*/\1/')
   echo "required toolchain: $RUST_TOOLCHAIN"

   rustup toolchain install "$RUST_TOOLCHAIN"
   # Sanity check — should list the nightly alongside stable:
   rustup toolchain list
   ```

   The build does not need this nightly to be the default toolchain; corrosion picks it up by name. If you ever bump the ClickHouse checkout to a newer Antalya tag and `cmake` complains about a different missing nightly, just rerun the snippet above — it always reads the value from source.

5. Build with Homebrew's Clang/LLD (Apple's system Clang is **not** supported):

   ```bash
   cd ~/src/github.com/altinity/ClickHouse
   mkdir -p build
   export PATH="$(brew --prefix llvm)/bin:$PATH"
   cmake -S . -B build -G Ninja \
     -DCMAKE_BUILD_TYPE=RelWithDebInfo \
     -DCMAKE_C_COMPILER="$(brew --prefix llvm)/bin/clang" \
     -DCMAKE_CXX_COMPILER="$(brew --prefix llvm)/bin/clang++" \
     -DCMAKE_AR="$(brew --prefix llvm)/bin/llvm-ar" \
     -DCMAKE_RANLIB="$(brew --prefix llvm)/bin/llvm-ranlib"
   cmake --build build --target clickhouse
   # Resulting binary: build/programs/clickhouse
   ```

   If linking fails with `ld: archive member '/' not a mach-o file in ...`, double-check that `-DCMAKE_AR=$(brew --prefix llvm)/bin/llvm-ar` is set (Apple's `ar` does not support GNU thin archives).

6. Copy the built binary into the cache directory using the exact filename the tests look for. The filename suffix is `safeFileName(AntalyaImageRef)` — every char outside `[A-Za-z0-9._-]` becomes `_` — which we reproduce here from `$ANTALYA_IMAGE_REF`:

   ```bash
   mkdir -p ~/.cache/embedded-clickhouse
   ANTALYA_BIN_SUFFIX=$(printf '%s' "$ANTALYA_IMAGE_REF" | LC_ALL=C sed -E 's/[^A-Za-z0-9._-]/_/g')
   DEST=~/.cache/embedded-clickhouse/clickhouse-${ANTALYA_BIN_SUFFIX}
   cp ~/src/github.com/altinity/ClickHouse/build/programs/clickhouse "$DEST"
   chmod +x "$DEST"
   echo "installed: $DEST"
   ```

   If you're unsure what filename the loader expects, just run the Antalya tests once — the failure message prints the exact path it looked for.

7. Re-run the embedded-CH tests:

   ```bash
   go test ./pkg/server/... -run Antalya -count=1 -v
   ```

If you want to refresh the macOS binary after `AntalyaImageRef` is bumped, re-run step 2 to refresh `ANTALYA_IMAGE_REF`/`ANTALYA_IMAGE_TAG`, then repeat steps 3 (`git pull && git checkout && git submodule update`), 4 (the pinned Rust nightly may have changed), 5, and 6. The cached binary is keyed by `AntalyaImageRef`, so bumping that constant invalidates the cache automatically.

## Suggested Contributor Workflow

For a typical code change:

1. Build the binary with `go build -o altinity-mcp ./cmd/altinity-mcp`
2. Run focused tests for the area you changed
3. Run `go test ./...`
4. OAuth e2e tests run automatically — no extra flags needed

## Troubleshooting

### Docker Tests Fail Immediately

- Verify Docker is running
- Verify container pulls are allowed from the current environment
- Re-run the failing package with `-v` to see which container-backed test failed

### OAuth E2E Test Fails with Standard ClickHouse Images

The OAuth e2e tests require the Antalya ClickHouse build (`altinity/clickhouse-server:25.8.16.20001.altinityantalya`). Standard upstream images do not provide the `token_processors` support these tests depend on. The test pulls this image automatically via testcontainers.
