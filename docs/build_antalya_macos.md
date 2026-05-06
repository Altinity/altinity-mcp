---
description: 'Step-by-step guide for building Altinity Antalya ClickHouse from source on macOS'
sidebar_label: 'Build Antalya on macOS'
sidebar_position: 16
slug: /development/build-osx-antalya
title: 'Build Antalya ClickHouse on macOS'
keywords: ['macOS', 'Mac', 'Apple Silicon', 'build', 'Antalya']
doc_type: 'guide'
---

# Build Antalya ClickHouse on macOS

This guide takes you from a clean macOS install to a working `clickhouse` binary built from the Antalya fork. It covers Apple Silicon (`arm64`) and Intel (`x86_64`) on macOS 10.15+. Total time: 30–60 minutes for the first build, depending on hardware and network.

## TL;DR

```bash
# 1. Prerequisites (one-time)
brew install ccache cmake ninja libtool gettext llvm lld binutils \
             grep findutils nasm bash rust rustup
rustup toolchain install nightly-2025-07-07 --profile minimal

# 2. Clone with submodules
git clone --recurse-submodules https://github.com/Altinity/ClickHouse.git
cd ClickHouse
git checkout antalya-26.1   # or another antalya-* branch

# 3. Configure
CC=/opt/homebrew/opt/llvm/bin/clang \
CXX=/opt/homebrew/opt/llvm/bin/clang++ \
cmake -S . -B build -G Ninja

# 4. Build
ninja -C build clickhouse
# → build/programs/clickhouse  (~625 MB)
```

If you only want the path to the resulting binary: **`build/programs/clickhouse`**.

The rest of this guide covers each step in detail and the pitfalls that aren't obvious from the upstream `build-osx.md`.

## Prerequisites

### macOS version

* **10.15 (Catalina) or later.** `CMAKE_OSX_DEPLOYMENT_TARGET` is hardcoded to `10.15`; older runtimes are not supported.
* Both architectures are supported. The build auto-detects `arm64` vs `x86_64`. Do **not** use universal/fat binaries — pick the native arch on your machine.

### Apple toolchain

Install Xcode Command Line Tools — only the headers and `ld` are needed; the full Xcode app is optional.

```bash
xcode-select --install
```

You will need the system linker (`/usr/bin/ld`) on the path; ClickHouse passes `--ld-path=/usr/bin/ld` explicitly. Apple's `clang` (the one Xcode ships) is **not** used; build only with Homebrew Clang (see below).

### Homebrew

If you don't have it:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Build tools

```bash
brew install ccache cmake ninja libtool gettext llvm lld binutils \
             grep findutils nasm bash rust rustup
```

What each one does and why it's needed:

| Tool | Why ClickHouse needs it |
|---|---|
| `cmake` | Build-system generator. Need ≥ 3.27. Homebrew has 4.x which works fine. |
| `ninja` | Build executor invoked by cmake. Much faster than `make`. |
| `llvm` | Provides Homebrew Clang ≥ 22.x at `/opt/homebrew/opt/llvm/bin/clang`. **The only supported compiler.** Apple Clang is rejected (missing flags / std-library conflicts). |
| `lld` | LLVM's linker; some build steps assume `ld.lld` is on the path even though final link uses `/usr/bin/ld`. |
| `ccache` | Compiler cache. Massively reduces incremental rebuild and worktree-rebuild times. cmake auto-wires it if found. |
| `nasm` | Required by some compression contribs (e.g. zlib-ng's x86 SIMD path; harmless on `arm64`). |
| `rustup` | Rustup toolchain installer. The Rust components below need a *specific* nightly that you install through `rustup`, not the `rust` formula's stable. |
| `rust` | Pulls in `cargo` available on `PATH`; superseded by rustup but doesn't hurt to have. |
| `bash` | Several build scripts use bash 4+ features. macOS ships bash 3.2; the build will fail with cryptic "associative array" errors if `/opt/homebrew/bin/bash` isn't ahead of `/bin/bash` on `PATH`. |
| `binutils`, `grep`, `findutils`, `gettext`, `libtool` | GNU variants that some contrib build steps depend on. macOS BSD versions silently miss flags (e.g. `find -regextype`) and produce confusing failures. |

On Intel Macs, replace `/opt/homebrew/...` with `/usr/local/...` throughout.

### Rust nightly toolchain (pinned)

ClickHouse's Rust components (`prql`, `skim`) require an exact nightly. Check the pin first:

```bash
grep Rust_TOOLCHAIN contrib/corrosion-cmake/CMakeLists.txt
# → set(Rust_TOOLCHAIN "nightly-2025-07-07")
```

Then install **that exact** version:

```bash
rustup toolchain install nightly-2025-07-07 --profile minimal
```

`--profile minimal` skips docs / extras. Without the explicit version, cmake configure fails with:

```
Cannot find nightly-2025-07-07 Rust toolchain.
You can install it with 'rustup toolchain install nightly-2025-07-07'
```

Network note: rustup pulls from `static.rust-lang.org`. In sandboxed/air-gapped setups the host must be reachable; otherwise rustup hangs in `error sending request`.

## Clone the repository

```bash
git clone --recurse-submodules https://github.com/Altinity/ClickHouse.git
cd ClickHouse
```

Pick the branch you want to build:

```bash
git checkout antalya-26.1
# or:
git checkout antalya-26.3
# or any branch under refs/heads/antalya-*
```

> **Building specifically for altinity-mcp tests?** Pin to the tag matching `AntalyaImageRef` from `internal/testutil/embeddedch/embeddedch.go` instead of using a branch — see [development_and_testing.md](./development_and_testing.md) for the snippet and the cache-install step.

If you already cloned **without** `--recurse-submodules`, run:

```bash
git submodule update --init --recursive --jobs 8
```

This step alone is the slowest part of a fresh setup. ClickHouse has ~150 git submodules (LLVM, Arrow, Boost, BoringSSL, Postgres, …); the working trees together are ~7.9 GB, hundreds of thousands of files. **Expect 5–15 minutes** depending on disk speed; most of that is filesystem walk, not network.

### Speeding up additional worktrees (optional)

If you make a `git worktree add` later, its `contrib/` starts empty and the per-submodule init repeats. On macOS (APFS) you can skip the disk write by clonefile-copying a populated `contrib/` from another worktree:

```bash
# In a fresh worktree:
rm -rf contrib
cp -c -R /path/to/other/worktree/contrib ./contrib

# Fix gitdir pointers in copied submodule .git files (each must point at the
# central .git/modules/<sub>/ dir of the main repo)
find contrib -name .git -type f | while read f; do
    rel="${f#./}"
    rel="${rel%/.git}"
    main="/path/to/main/.git/modules/$rel"
    [[ -d "$main" ]] && echo "gitdir: $main" > "$f"
done

git submodule update --init --recursive   # ~2 seconds; verifies pointers
```

This turns 12 minutes of submodule init into ~3 minutes of metadata walk plus 2 seconds of git verification. Without it, every new worktree pays the full materialization cost.

## Configure the build

```bash
CC=/opt/homebrew/opt/llvm/bin/clang \
CXX=/opt/homebrew/opt/llvm/bin/clang++ \
cmake -S . -B build -G Ninja
```

What each part means:

* **`CC` / `CXX`** — explicit Homebrew Clang. cmake's auto-detect picks Apple Clang first on macOS, which the build does **not** support. Setting these env vars is mandatory.
* **`-S .`** — source directory.
* **`-B build`** — out-of-source build directory. Anything under `build/` is generated; safe to delete and re-configure.
* **`-G Ninja`** — Ninja generator. Faster than Make; required for the dependency graph this codebase produces.

Configure takes 2–4 minutes (downloads no extra code; just walks the tree). Successful end-of-output looks like:

```
-- Will build ClickHouse 26.1.6.20001.altinityantalya revision 54511
-- compiler C   = /opt/homebrew/opt/llvm/bin/clang ...
-- compiler CXX = /opt/homebrew/opt/llvm/bin/clang++ ...
-- LINKER_FLAGS =  -Wl,-no_warn_duplicate_libraries --ld-path=/usr/bin/ld -Wl,-U,_inside_main
-- Configuring done (XX.Xs)
-- Generating done (X.Xs)
-- Build files have been written to: /path/to/build
```

### Build types

By default the build is `RelWithDebInfo` (release optimization with debug info). Other options:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug   -G Ninja  # build_debug
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -G Ninja  # smaller, no debuginfo
```

Convention is one build dir per build type:

```
build         # RelWithDebInfo (default)
build_debug   # Debug
build_asan    # AddressSanitizer
```

## Build the binary

```bash
ninja -C build clickhouse
```

This is what takes the longest. Numbers from a 2023 M2 Pro:

| Build | Time |
|---|---|
| First build (clean `build/`, no ccache) | 25–40 min |
| Incremental, single `.cpp` change | 30–90 s |
| Incremental, header touched in `Common/` | 5–15 min |
| Different worktree, ccache hits via `-ffile-prefix-map=` | 3–5 min plus link |

The build compiles ~13,500 translation units. Final link of the `programs/clickhouse` executable is single-threaded and takes 30–60 s on its own.

Successful end-of-output:

```
[13517/13518] Linking CXX executable programs/clickhouse; ...
```

Verify the binary:

```bash
./build/programs/clickhouse --version
# → ClickHouse local version 26.1.6.20001.altinityantalya.
```

`clickhouse` is a multi-call binary. The CLI tools you'd expect (`clickhouse-client`, `clickhouse-server`, `clickhouse-local`, `clickhouse-keeper`, …) are all dispatched from this one executable based on argv[0] or the first argument:

```bash
./build/programs/clickhouse client --query "SELECT 1"
./build/programs/clickhouse local  --query "SELECT 1"
./build/programs/clickhouse server --config=/path/to/config.xml
```

## Common failure modes

### `Unable to find current revision in submodule path 'contrib/<X>'`

Submodules out of sync after a branch switch. Fix:

```bash
git submodule update --init --recursive --jobs 8
```

### `No SOURCES given to target: _curl` (during cmake configure)

Same root cause — usually means the curl submodule isn't checked out at the right ref because submodules were not updated after a branch switch. Run the command above.

### `error: cannot find -lc++abi` or `error: cannot find -lc++`

Build is trying to use Apple Clang, which links against the system C++ standard library, conflicting with what ClickHouse expects. Re-configure with `CC` / `CXX` pointing at Homebrew Clang as shown above; delete `build/CMakeCache.txt` first if it has the wrong compiler stuck in it.

### `CMakeCache.txt` references someone else's path (`/Users/<other>/...`)

You picked up a `build/` directory that was configured on a different machine or under a different user. cmake stores absolute paths in `CMakeCache.txt`. Wipe and reconfigure:

```bash
rm -rf build && cmake -S . -B build -G Ninja
```

### `Cannot find nightly-XXXX-XX-XX Rust toolchain`

You don't have the *exact* pinned nightly. Don't try a different nightly; the codegen lockfiles depend on the exact version. Install the one cmake asks for via `rustup toolchain install <version>`.

### `error sending request for url (https://static.rust-lang.org/...)` (timeout)

Rustup can't reach its mirror. Either:

1. Check your network / VPN reaches `static.rust-lang.org`.
2. In sandboxed environments (corporate, isolated dev VMs), add the host to your egress allowlist.

### `bash: associative arrays not supported` or similar in build helpers

You're hitting macOS's bash 3.2 instead of Homebrew's bash 5.x. Make sure `/opt/homebrew/bin` (or `/usr/local/bin` on Intel) is **before** `/bin` and `/usr/bin` in `PATH`.

### `linker command failed with exit code 1` near end of build

Almost always a wrong-compiler / wrong-libc++ mix. Confirm with:

```bash
grep CMAKE_C.*COMPILER build/CMakeCache.txt
```

Both lines should point inside `/opt/homebrew/opt/llvm/bin/`. If they don't, see the cache-cleanup step above.

## Running tests

The full stateless / stateful test suite runs in Docker via `praktika`. For a local non-Docker run of one test:

```bash
python3 -m ci.praktika run "Stateless tests (arm_binary, parallel)" \
    --no-docker --test 03749_cloud_endpoint_auth_precedence
```

Most stateless tests need a running ClickHouse server; `praktika` brings one up. Single-binary smoke tests (`--query` against `clickhouse local`) can be run directly without `praktika`.

Build-time unit tests (gtest):

```bash
ninja -C build clickhouse_unit_tests
./build/src/unit_tests_dbms --gtest_filter='OAuthLogin.*'
```

## Where everything ends up

| Path | What |
|---|---|
| `build/programs/clickhouse` | The single multi-call binary you'll actually run. |
| `build/programs/server/config.xml`, `users.xml` | Default server config (copies of `programs/server/*.xml`). |
| `build/src/unit_tests_dbms` | gtest binary for unit tests. |
| `build/src/libdbms.a` | The big static library. ~hundreds of MB. |
| `~/.ccache/` | ccache state (default; configurable). Persists across worktrees and `build/` wipes. |

## Where to go next

* General developer setup: `docs/en/development/developer-instruction.md`
* Upstream macOS build (different toolchain choices, less Antalya-specific): `docs/en/development/build-osx.md`
* Antalya OAuth login configuration (uses the `clickhouse client` binary you just built): `docs/en/interfaces/cli-oauth-login.md`

If something fails that isn't covered above, check `build/CMakeError.log` first — it usually has a clear "tried this, got that" record. For long-tail issues, the Antalya repo's issue tracker is at https://github.com/Altinity/ClickHouse/issues.
