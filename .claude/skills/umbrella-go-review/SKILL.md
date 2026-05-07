---
name: umbrella-go-review
description: Use when the user asks for a multi-perspective review of a Go diff, PR, branch, commit range, or commit hash. Triggers on requests like "review this PR", "umbrella review", "do a full review", "deep review of branch X", or any Go-codebase code review where multiple independent angles (security, perf, concurrency, lifetime, compat, tests, etc.) should be considered before producing a consolidated report. Adapted for altinity-mcp from the upstream ClickHouse `umbrella-clickhose-review` skill — same workflow, Go-flavored subagents (drops C++ headers + lifetime; reframes security around OAuth/secret-handling, perf around GC/goroutines/channels, compat around helm-chart/image-rolling/OAuth-config rename).
---

# Umbrella Go Review

Multi-perspective code review for Go diffs in altinity-mcp (or any Go codebase). Prepare neutral shared context, dispatch specialized review subagents in parallel, validate findings, and produce one consolidated high-signal report.

## When to Use

- User provides a PR number/URL, branch name, commit hash, commit range, or explicit diff spec and wants a thorough review.
- Change touches non-trivial Go code (auth, OAuth, helm chart, MCP transport, ClickHouse client, CLI/env config, settings reflection).
- User explicitly invokes "umbrella review" or "full review".

**Don't use for:** trivial doc-only changes, single-line fixes, or when user asks for a quick scan only.

## Workflow

### 1. Resolve the diff

Determine input type and gather material:

- **PR (number or URL):** `gh pr view <N> --json title,body,baseRefName,headRefName,files,commits` and `gh pr diff <N>`.
- **Branch:** `git diff <base>...<branch>` and `git log <base>..<branch>`. Default base is `main` unless specified.
- **Commit range / hash:** `git diff <range>`, `git log <range>`.
- **Explicit diff spec:** use as given.

Record: base ref, head ref, file count, commit messages, PR title/description.

### 2. Build neutral shared context

Before launching reviewers, prepare a single context block. **Facts only — no judgement.** Include:

**File / package map:**
- changed files grouped by package/component
- touched public APIs / config struct fields (flag/env tags) / helm values keys / OAuth surface / MCP transport
- touched tests, docs, build files, scripts, generated files
- likely hot paths (request handlers, validation, token issuance)
- likely user-facing behavior (HTTP responses, error surfaces, log fields)
- new or changed shared state (singletons, package-level vars, sync types)
- new or changed external inputs (HTTP request fields, env vars, CLI flags, OAuth claims, JWT contents)
- removed or relaxed tests
- large or binary files

**Behavior map (when applicable):**
- user/system entrypoints (HTTP routes, CLI commands)
- validation and dispatch layers
- state / cache interactions (in-memory state stores, JWKS cache, OIDC discovery cache)
- downstream integrations: ClickHouse client, upstream IdP HTTP, Kubernetes Secret reads
- error and panic-recovery paths (errors.Is chains, defer/recover, context cancellation propagation)
- state transitions and side effects
- important invariants the change appears to rely on

Only include facts visible from the diff, commit messages, PR metadata, and nearby code.

### 3. Dispatch subagents in parallel

Use the `Agent` tool with `subagent_type: "general-purpose"` and `model: "sonnet"` (cheaper but capable). Send all applicable subagents in a **single message with multiple Agent tool calls** so they run concurrently.

Each subagent gets:
- the neutral shared context (verbatim)
- the diff
- its assigned scope and prompt (below)
- the **General review rules** and **Required output format** (below)

Skip subagents that clearly do not apply (e.g. concurrency review on a docs-only change). Always run subagents 1, 2, 3, 7, 11, 12. Run 13 (deep audit) only for complex / high-risk changes.

### 4. Aggregate

- Deduplicate findings across subagents.
- Verify file/line references and evidence against actual diff.
- Re-score severity when a subagent over- or under-states risk.
- Merge related findings sharing a root cause.
- Drop speculative / unsupported findings.
- Keep important-but-unproven concerns under **Needs verification**.
- Prefer actionable fixes over general advice.
- Surface cross-cutting themes only after concrete findings.
- If deep audit ran, preserve its coverage summary; drop its narrative.
- Classify failure behavior when relevant: success, handled error, fail-open, fail-closed, panic, context-canceled, partial update.

### 5. Produce the final report

Use the **Final report format** below. Omit empty sections except Summary, Reviewed scope, and Final verdict. Include Coverage summary when deep audit ran or when coverage gaps materially affect confidence.

---

## General review rules (give to every subagent)

```
Each subagent must:
- Review only from its assigned perspective.
- Inspect surrounding context when the diff alone is insufficient.
- Prefer concrete findings over generic advice.
- Avoid style nitpicks unless they create real ambiguity, risk, or maintenance cost.
- Avoid duplicate findings already obvious from its own previous points.
- Mark uncertainty explicitly.
- Do not assume behavior not visible from code or provided context.
- If a finding depends on missing context, say exactly what context is missing.

False positives are costly. Do not report a finding unless there is a plausible
concrete risk, maintenance problem, user impact, or reviewability problem.
```

## Required subagent output format

```
Subagent: <name>
Scope: <one-line scope>

Findings:
1. Title: <short finding title>
   Risk score: <0-100>
   Confidence: high | medium | low
   Severity: blocker | major | minor | nit | follow-up
   Files/lines: <file:line or file/range; "unknown" only if unavailable>
   Evidence: <concrete evidence from diff/code>
   Risk: <why this matters>
   Proposed fix: <specific fix or next step>
   Notes: <optional caveats>

2. ...

Needs verification:
- <important but not fully proven concern, with exact missing context>
```

**Risk score guidance:**
- 90-100: likely blocker; correctness, data loss, security, serious compat, race/deadlock, severe hot-path regression, secret leak.
- 70-89: major issue likely worth fixing before merge.
- 40-69: meaningful maintainability, operability, test, or perf concern.
- 20-39: minor but concrete improvement.
- 0-19: nit / optional cleanup; usually do not report.

---

## Subagents catalog

For each subagent: `Scope` is the one-line scope to put in the output header; `Prompt` is the body to pass.

### 1. UX / feature sanity / public contract

**Scope:** UX, feature coherence, public API and behavioral contract.

**Focus:** feature UX and logical consistency; whether behavior matches user expectations; public Go API and contract changes (exported funcs, struct fields with json/yaml tags, helm values, CLI flags, env vars); HTTP response surface (status codes, body shape, header values like `WWW-Authenticate`); exposed interfaces, defaults, error semantics, invariants; misuse-prone APIs; narrow implementations where a general idiomatic alternative exists; long-term maintainability of user-visible model; surprising behavior, misleading errors, confusing edges.

**Prompt:**
```
Review the diff from a UX, feature-sanity, and public-contract perspective.
Look for ad hoc behavior, confusing semantics, poor defaults, surprising error
behavior, unclear invariants, misuse-prone APIs, and places where the
implementation solves a narrow case while a more idiomatic general design
exists. Public surfaces in this codebase include: exported Go funcs/types,
struct fields exposed via `json`/`yaml` tags, helm values keys, CLI flag
names, env var names (often `MCP_*` / `CLICKHOUSE_*`), HTTP response shapes,
WWW-Authenticate header content, OAuth/MCP spec compliance. Report only
concrete issues with user or caller impact.
```

### 2. Code architecture / design

**Scope:** Architecture, design, component cooperation.

**Focus:** design inconsistencies; accidental complexity; unclear or implicit behavior; SOLID / responsibility violations; leaky abstractions; tight coupling / low cohesion; non-idiomatic Go patterns (e.g. interface bloat, unnecessary type assertions, `interface{}`/`any` where a concrete type fits, package cycles, init() side effects); encapsulation / layering (`cmd/` vs `pkg/` vs `internal/`); partial / asymmetric fixes across similar components.

**Prompt:**
```
Review the diff for architecture and design issues: inconsistencies, accidental
complexity, unclear or implicit behavior, responsibility/SOLID violations,
leaky abstractions, tight coupling, low cohesion, non-idiomatic Go patterns,
improper encapsulation/layering across cmd/ vs pkg/ vs internal/, and
partial/asymmetric fixes across sibling components or similar code paths.
Explain how the moving parts interact and where the design creates future
maintenance risk.
```

### 3. Ockham / YAGNI / unnecessary diff

**Scope:** Avoidable, unrelated, no-op, or premature changes.

**Focus:** unrelated cleanup mixed with core change; no-improvement edits; speculative generality; unnecessary abstractions; no-op rewrites; review-impeding churn; changes belonging in separate commits or follow-ups; unused exports left over from refactors.

**Prompt:**
```
Review the diff for unnecessary diff: avoidable, unrelated, speculative, or
no-op changes that do not improve behavior, performance, clarity, safety, or
reviewability. Identify which changes should be removed, split into separate
commits, or postponed.
```

### 4. Security / OAuth / secret handling / trust boundary

**Scope:** Security-sensitive behavior and trust boundaries.

**Focus:** OAuth flow correctness (RFC 6749/8707/9728/MCP spec); JWT/JWE validation (signature, iss, aud, exp, nbf, scopes, audience byte-equality); secret handling in code (env-var injection, K8s Secret references, never inline in helm values, never on argv, never `cat`/`echo` of unfamiliar config files); trust-boundary expansion (newly-public surfaces, removed auth checks, weakened audience matching); user-controlled inputs reaching SQL/HTTP/file-system; logging of credentials, bearer tokens, JWT contents; redirects, open-redirect risks in OAuth callback handlers; PKCE; DCR client_id JWE; refresh-token rotation; CORS; cookie attributes if any; defense-in-depth across MCP and ClickHouse.

**Prompt:**
```
Review the diff for security issues and trust-boundary expansion in this
OAuth/MCP/ClickHouse-client codebase. Pay special attention to:
- OAuth flow correctness against MCP authorization spec 2025-11-25 + RFCs
  6749, 8707 (resource indicators / aud byte-equality), 9728 (resource
  metadata), 6750 (Bearer challenges).
- JWT/JWE validation completeness: signature, iss, aud, exp, nbf, scopes.
- Secret handling: env-var injection from K8s Secrets, no inline values in
  helm values.yaml, no secrets on argv (`docker login --password`,
  `kubectl create --from-literal=` are exposure points), no `cat` of
  unfamiliar config files, no log lines that print bearer tokens.
- Trust-boundary expansion: newly-exposed surfaces, removed auth checks,
  weakened audience/issuer matching, defense-in-depth between MCP and
  ClickHouse.
- Open-redirect / SSRF in callback handlers and resource-indicator parsing.
- PKCE on both legs (MCP-client→us and us→upstream IdP); DCR client_id JWE
  rotation; refresh-token rotation; CORS; cookies if any.
For suspicious code, compare old callers vs new callers and test boundary
assumptions with concrete minimal/malicious inputs.
```

### 5. Performance / hot-path (Go-flavored)

**Scope:** Runtime performance and scalability.

**Focus:** GC pressure (allocations on per-request paths, escapes from stack to heap, slice/map reallocation in loops, `string` ↔ `[]byte` conversions); goroutine leaks (started without bounded lifetime, blocked on uncancelable channels, no context propagation); channel/mutex contention (single global Mutex on hot paths, RWMutex with always-write workload, sync.Map misuse); inefficient I/O (uncached HTTP `client.Get` per request, missing `defer resp.Body.Close()`, no `io.LimitReader`, blocking syscalls under locks); pathological complexity, accidental O(N²) on user-controlled sizes; expensive logging in hot paths (string formatting before level check); JSON encoding/decoding choices (`json.Encoder` vs `Marshal` allocations); `defer` overhead in tight loops; wrong sync primitive choice.

**Prompt:**
```
Review the diff from a Go performance perspective, especially hot paths
(HTTP request handling, OAuth token validation, MCP transport).

Look for:
- Allocations on per-request paths (slice/map growth without preallocation,
  `string`↔`[]byte` round-trips, escapes to heap, unnecessary `interface{}`
  boxing).
- Goroutine lifecycle: started without bounded lifetime, blocked on
  uncancelable channels, no context propagation, leaked under cancellation.
- Channel / mutex contention: single global lock on hot paths, RWMutex
  used for always-write workload, sync.Map misuse, sync.Once outside
  init.
- I/O patterns: HTTP `client.Get` without timeout/context, missing
  `defer resp.Body.Close()`, no `io.LimitReader`, blocking syscalls under
  locks, no JWKS/OIDC caching where it should exist.
- Pathological complexity on user-controlled sizes; logging in hot paths
  with eager formatting.
- Wrong sync primitive choice; `defer` overhead in tight loops.

Report only issues that plausibly affect realistic workloads or scalability.
```

### 6. Documentation / comments / changelog

**Scope:** Understandability for users and maintainers.

**Focus:** missing user-facing docs (under `docs/`); misleading / incomplete docs; godoc comments for non-obvious exported funcs/types; outdated comments; unclear error / log messages; CHANGELOG quality; migration notes for incompatible behavior (helm values rename, env-var rename, OAuth-config rename); typos in user-visible strings, logs, docs, comments, identifiers.

**Prompt:**
```
Review documentation and explanatory quality: user-facing docs under docs/,
godoc on exported funcs/types where the API isn't obvious from the name,
comments for non-obvious logic, CHANGELOG/release-note quality, migration
notes for breaking helm-values/env-var/config-field renames, diagnostics,
log lines, error messages, and typos. Do not ask for comments on obvious
code; focus on places where missing or misleading explanation creates user
or maintenance risk.
```

### 7. Code quality / correctness / maintainability

**Scope:** Local code quality and bug-proneness.

**Focus:** likely bugs / edge-case errors; clarity / readability; naming; defensive coding; fragile assumptions; error-prone control flow; duplicated logic; confusing conditionals; magic constants; `errors.Is`/`errors.As` correctness vs string matching; nil-pointer dereferences; closure-capture-of-loop-variable bugs (`for _, x := range … { go func() { use(x) }() }` pre-Go 1.22); slice aliasing; map iteration nondeterminism leaking into output; integer overflow / lossy conversions in untrusted-input paths; ignored errors (`_ = err`); panics in library code.

**Prompt:**
```
Review the diff for Go code quality, correctness, and maintainability:
likely bugs, unclear code, poor naming, fragile assumptions, missing
defensive checks, duplicated logic, magic constants, ignored errors,
errors.Is/As misuse, nil-pointer dereferences, closure-capture-of-loop-var
bugs, slice aliasing, map iteration order leaking out, integer overflow
on untrusted inputs, and panics in library code. Prefer concrete bug
risks over style preferences.
```

### 8. Operability / DevOps / observability

**Scope:** Production introspection, debuggability, alerting.

**Focus:** introspection of behavior; debuggability of failure modes; useful logs / errors (zerolog field hygiene, no PII/credential leakage); metrics and counters; alertability of exceptional situations; missing context in diagnostics; safe degradation / recovery; background task visibility; operational impact of config / default changes; helm-chart pod startup health (livez/health probes); log level discipline (no debug-level secrets, no info-level log spam in hot paths).

**Prompt:**
```
Review the diff from an operability / DevOps perspective: introspection,
debugging, metrics, logging, alerting, production diagnostics, recovery,
and visibility into exceptional or background behavior. For zerolog log
lines specifically, check field naming consistency, no credential/PII
leakage, level appropriateness (debug vs info vs warn vs error), and
whether the log gives an operator enough context to act.
Flag cases where production issues would be hard to detect, debug, or
react to. Helm chart livez/health endpoints, CHI auto-secret references,
and K8s Secret env-var injection are part of the operability surface.
```

### 9. Concurrency / synchronization

**Scope:** Multithreading, shared state, synchronization.

**Focus:** shared mutable state across goroutines; data races detectable by `-race`; lifetime races (goroutine outlives the data it reads); missing / excessive / inconsistent locking; lock ordering, deadlocks; TOCTOU on map/struct mutation; `sync/atomic` vs Mutex correctness for value types; condition variables (rare in Go); reentrancy; blocking I/O under locks; goroutine pool / worker patterns; thread-safety of exposed APIs; undocumented goroutine-affinity assumptions; channel close panics; select-default starvation; `context.Context` propagation and cancellation handling.

**Prompt:**
```
Review the diff for Go concurrency issues: data races, lifetime races
(goroutine outliving data), locking consistency, lock ordering / deadlocks,
TOCTOU, sync/atomic correctness, blocking I/O under locks, goroutine pool
patterns, thread-safety of exported funcs/types, channel close panics,
select-default starvation, and context.Context propagation.
For each touched shared object, identify readers/writers, guards, relevant
call paths, and risky interleavings. Flag any goroutine started without a
clear lifetime or cancellation path.
```

### 10. Tests / regression risk

**Scope:** Validation adequacy and regression coverage.

**Focus:** missing tests for changed behavior; weak assertions; deleted / relaxed / over-normalized tests; missing negative tests; missing boundary cases (empty, length 1, huge, malformed, nil, invalid config); missing compatibility tests (env-var override semantics, helm values backward compat); missing security / concurrency / perf tests where relevant; brittle tests (testcontainers env assumptions, `time.Now()` flakes, port collisions on parallel runs); gaps between implementation risk and coverage. For altinity-mcp specifically: embedded-clickhouse tests need `TESTCONTAINERS_RYUK_DISABLED=true` in the sandbox.

**Prompt:**
```
Review test coverage and regression risk: missing tests, weak assertions,
untested edge cases, deleted/relaxed tests, missing negative tests, missing
compatibility/security/concurrency/performance coverage, brittle tests
(testcontainers, time.Now flakes, port collisions on parallel runs), and
gaps between changed behavior and validation.
Suggest specific tests to add or strengthen.
```

### 11. Compatibility / rollout / migration

**Scope:** Cross-version, cross-deployment, cross-config safety.

**Focus:** backward / forward compatibility for helm-values keys, env-var names, CLI flag names, config struct field tags (`yaml:`/`json:`/`flag:`/`env:`), MCP-issued artifact formats (DCR client_id JWE, refresh-token JWE, self-issued access-token JWT — all carry `kid` for rotation); legacy compat windows (kid-less SHA256 fallback during HKDF rotation); image-tag rollout (multi-arch manifest, arm64 demo cluster); helm chart upgrade idempotency; safe defaults; existing K8s Secrets that may not have new keys; existing claude.ai connectors with cached DCR client_ids that must keep decrypting after `signing_secret` is relocated.

**Prompt:**
```
Review the diff for compatibility and rollout risks specific to this
helm-deployed Go service:
- Renames in helm-values keys, env-var names, CLI flag names, config
  struct yaml/json/flag/env tags — these break existing deploy/<env>/
  mcp-values.yaml files and OAuth-config secrets unless aliased or
  documented.
- MCP-issued artifact formats (DCR client_id JWE, refresh-token JWE,
  self-issued access-token JWT) all carry a `kid` header for rotation.
  Check whether legacy artifacts (no kid, SHA256-derived) still decrypt
  during the rotation window.
- Image rollout: multi-arch manifest, arm64 demo cluster — single-arch
  pushes break the deployment with `exec format error`.
- Helm chart upgrade idempotency; safe defaults that don't surprise
  existing operators.
- claude.ai's cached connector state (DCR-issued client_id) must keep
  working post-deploy unless a re-add is acceptable.
Flag new validation or behavior changes that may break existing
deployments, configs, or active OAuth sessions.
```

### 12. Repository impact / generated / binary artifacts

**Scope:** Repository hygiene; accidental artifacts.

**Focus:** large files; binary files; accidentally committed generated files; vendored dependency blobs; built `altinity-mcp` / `jwe-token-generator` binaries left in the worktree by `scripts/build-mcp-image.sh`; archives / executables / datasets / model artifacts; build outputs; repo bloat; test data that should be generated or downloaded; `.terraform/` provider caches; tfstate files (must never be committed — they carry secrets).

**Prompt:**
```
Review the diff for repository-impact issues: large files, binary
artifacts, generated files, vendored blobs, archives, compiled outputs
(altinity-mcp / jwe-token-generator binaries from local builds),
.terraform/ caches, tfstate files (these carry Auth0 client_secrets in
plaintext — must NEVER be committed), datasets, and unnecessary
repository bloat.
Flag anything that should not be committed or should be generated /
downloaded at test time instead.
```

### 13. Deep audit / transition and fault-injection (high-risk only)

**Scope:** Deep transition and fault analysis for complex / high-risk changes.

**When to run:** OAuth flow changes; JWT/JWE format changes; config-struct rename or removal; helm chart shape changes; MCP transport handler changes; multi-step state transitions (auth code issuance → redemption → token refresh); new K8s Secret references; **Skip for trivial / local changes.**

**Focus:** call graph and entrypoints; caller assumptions and trust-boundary changes; request/event flow through validation, dispatch, state changes, outputs, side effects; key invariants before/after each transition; logical branch coverage; fault categories derived from actual changed components (malformed JWT, expired token, wrong aud, missing K8s Secret key, upstream IdP timeout, JWKS rotation mid-request, context cancellation, goroutine cancellation, partial helm rollout); fail-open vs fail-closed for security paths; cross-component interactions (MCP server ↔ ClickHouse, MCP server ↔ upstream IdP, MCP server ↔ K8s API).

**Prompt:**
```
Review the diff in deep audit mode. First build a lightweight call graph
and transition matrix for the changed behavior: HTTP entrypoints,
validation/dispatch, state/cache interactions (in-memory state stores,
JWKS cache, OIDC discovery cache), downstream integrations (ClickHouse,
upstream IdP, K8s Secret reads), state changes, outputs, side effects,
and error/panic propagation.

List the key invariants and check whether each transition preserves them.

Define logical fault categories from the actual code under review, then
test them by reasoning through: success, handled error, fail-open,
fail-closed, panic, context.Canceled, context.DeadlineExceeded, malformed
input, boundary input, shutdown, and concurrent-update paths as
applicable.

For mutation-heavy paths (token issuance, refresh-token rotation,
DCR registration), analyze panic/cancellation after each intermediate
state change and verify rollback, cleanup, and invariants.

For critical shared-state paths (in-memory state store, JWKS cache),
write plausible interleavings and check for race, deadlock, lifetime,
and partial-update hazards.

Report only confirmed defects. Keep speculative concerns under "Needs
verification". Include a short coverage summary: reviewed entrypoints,
transitions, fault categories, skipped areas, and assumptions.
```

---

## Final report format

```
# Review report: <diff spec / PR / branch>

## Summary
<neutral summary of the change and high-level verdict>

## Reviewed scope
- Diff: <input>
- Base: <base>
- Files changed: <count>
- Main moving parts:
  - <component>: <files / role>

## Missing context
- <omit section if none>

## Blockers
1. <finding>
   Risk score: <0-100>
   Sources: <subagents>
   Files/lines: <...>
   Evidence: <...>
   Impact: <...>
   Proposed fix: <...>

## Major issues
...

## Minor issues / improvements
...

## Needs verification
- <concern + exact missing check/context>

## Suggested commit / diff split
- Core refactoring / behavior changes:
  1. <step>
  2. <step>
- Separate follow-ups:
  - <unrelated cleanup / docs / tests / bug fix>

## Tests to add or strengthen
- <specific test suggestions>

## Coverage summary
- Entry points reviewed: <omit if not applicable>
- Transitions reviewed: <omit if not applicable>
- Fault categories checked: <omit if not applicable>
- Deferred / not covered: <omit if none>
- Main assumptions: <omit if none>

## Final verdict
Status: approve | request changes | block
Minimum required actions:
- <action>
```

Omit empty sections except Summary, Reviewed scope, and Final verdict.

---

## Tone and quality bar

- Strict but neutral.
- High-signal findings only.
- No generic checklists dumped on the user.
- No praise for every checked area; no "looks good" sections.
- Findings must be specific enough to act on.
- Suggest small surgical fixes over broad rewrites.
- Keep subagent output plain and structured so aggregation is reliable.

## Common mistakes

- Launching subagents serially instead of in one parallel batch.
- Letting subagents write the final user report (they must not).
- Forwarding low-confidence speculation as findings instead of "Needs verification".
- Skipping the neutral context step — reviewers then duplicate exploration work.
- Running deep audit (#13) on trivial diffs — wasteful.
- Including "looks good" sections or padding the report.
- Reviewing OAuth changes without consulting the actual MCP authorization
  spec (2025-11-25) — assumptions go stale fast.
- Confusing the trust boundary: in `forward` mode the bearer is the upstream
  IdP's id_token (passes through to ClickHouse for re-validation); in
  `gating` mode the bearer is a self-issued HS256 JWT (MCP is the only
  validator). Many findings change shape based on which.
