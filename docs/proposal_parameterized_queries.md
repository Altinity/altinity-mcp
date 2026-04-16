# Parameterized Query Arguments for `execute_query` (+ read-only description fix)

## Motivation

Today, `execute_query` takes a single `query` String parameter. Any value a caller wants ClickHouse to see — including user-supplied binary-ish content like HTML, JSON, CSV rows, markdown, etc. — must be inlined into the SQL text as a string literal. This is painful in three separate ways:

### 1. SQL string-literal escaping bugs

ClickHouse's `Values` format consumes `\` as an escape character inside `'...'` literals. Callers that legitimately generate content containing `\` (e.g. JS with `\"` for embedded HTML attributes) silently get their content rewritten on insert:

```
Caller writes:  'el.innerHTML = "<div class=\"x\">"'
CH stores:      'el.innerHTML = "<div class="x">"'   ← JS now has a syntax error
```

A real incident of this has been observed in production. The caller has no indication the corruption happened — the INSERT succeeds. The escape rules are different again for `'` (double it), `\n` (interpreted), tab (interpreted), etc., so callers must maintain a perfect escape table to avoid corruption.

### 2. Per-tool-input size cap (observed in claude.ai chat)

The claude.ai chat client enforces an undocumented per-tool-invocation size cap on MCP tool arguments. An INSERT whose inlined content pushes the `query` string past roughly 30 KB gets refused client-side before reaching this server. The content rides *inside the SQL text* today; a parameter-based encoding would let the same content ride as a separate JSON value, which compresses better and sidesteps the chat-side heuristic even if the payload is identical in byte count. (The server-side MCP protocol has no such cap; it's purely a claude.ai-client artifact.)

### 3. Wasted tokens in agentic callers

When an LLM agent writes a multi-KB INSERT statement, every byte of the value lives in the agent's own conversation context as quoted SQL. A parameter-based call emits the SQL once (templated) and the value once (as a JSON string), which is often cheaper to generate and maintain in an agent loop.

The fix is small: plumb ClickHouse's existing parameterized query support through the MCP tool's input schema. The driver already supports it (`pkg/clickhouse/client.go:367`, `ExecuteQuery(ctx, query, args ...interface{})`); only the tool-schema exposure is missing.

A separate but related issue is fixed in the same PR: the query-parameter description hardcodes "In read-only mode, only SELECT/WITH/SHOW/DESC/EXISTS/EXPLAIN are allowed" regardless of `cfg.ClickHouse.ReadOnly`, which makes LLM callers refuse INSERTs on writable deployments. Trivial to make conditional.

---

## Design

### Change 1 — Conditional read-only text in the parameter description

**Files:** `pkg/server/server.go:1110` and `:1980` (the OpenAPI mirror).

Today both places unconditionally emit:

> "SQL query to execute. In read-only mode, only SELECT/WITH/SHOW/DESC/EXISTS/EXPLAIN are allowed."

The server already knows at tool-registration time whether it's running read-only (`cfg.ClickHouse.ReadOnly`). Make the second sentence conditional:

```go
queryDesc := "SQL query to execute."
if cfg.ClickHouse.ReadOnly {
    queryDesc += " Only SELECT/WITH/SHOW/DESC/EXISTS/EXPLAIN are allowed on this server."
}
```

Use `queryDesc` in both the MCP InputSchema (line 1110) and the OpenAPI parameter spec (line 1980). The `ReadOnlyHint`/`DestructiveHint` annotations at `:1578` already flip correctly — this is purely a cosmetic fix to remove model self-censorship on writable deployments.

### Change 2 — `parameters` field on `execute_query`

**Files:** `pkg/server/server.go:1098-1119` (RegisterTools), `:1744` (HandleExecuteQuery), `pkg/clickhouse/client.go` (ExecuteQuery — no signature change needed; existing variadic `args` path is used verbatim).

#### MCP tool schema addition

```go
executeQueryTool := &mcp.Tool{
    Name:        "execute_query",
    Title:       "Execute SQL Query",
    Description: "Executes a SQL query against ClickHouse and returns the results",
    Annotations: makeExecuteQueryAnnotations(cfg.ClickHouse.ReadOnly),
    InputSchema: map[string]any{
        "type": "object",
        "properties": map[string]any{
            "query": map[string]any{
                "type":        "string",
                "description": queryDesc,  // from Change 1
            },
            "parameters": map[string]any{
                "type": "object",
                "description": "Optional named parameters to bind to the query. " +
                    "Use ClickHouse's `{name:Type}` placeholders in the `query` text " +
                    "and supply values here. Values are bound as data (no SQL escaping); " +
                    "recommended for large strings or any value containing `'` or `\\`. " +
                    "Supported value types: string, number, boolean, null, array of the " +
                    "preceding (for `Array(T)` types).",
                "additionalProperties": true,
            },
            "limit": map[string]any{
                "type":        "number",
                "description": "Maximum number of rows to return (default: 100000)",
            },
        },
        "required": []string{"query"},
    },
}
```

`parameters` is optional — callers that don't pass it get today's exact behaviour.

#### Handler change in `HandleExecuteQuery` (`server.go:1744`)

Pseudo-code; structure follows the existing handler:

```go
func HandleExecuteQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    arguments := req.Params.Arguments.(map[string]any)

    queryArg, ok := arguments["query"]
    // ... existing validation ...
    query := queryArg.(string)

    // NEW: collect parameters, if any
    var boundArgs []interface{}
    if p, ok := arguments["parameters"]; ok && p != nil {
        params, ok := p.(map[string]any)
        if !ok {
            return errorResult("'parameters' must be an object")
        }
        for name, raw := range params {
            val, err := coerceParam(name, raw)
            if err != nil {
                return errorResult(fmt.Sprintf(
                    "parameter %q: %s", name, err))
            }
            boundArgs = append(boundArgs, clickhouse.Named(name, val))
        }
    }

    // ... existing client setup ...
    result, err := client.ExecuteQuery(ctx, query, boundArgs...)
    // ... existing result handling ...
}
```

`coerceParam` translates the JSON value into a Go type the driver can bind:

| JSON input | Go type | CH side |
|---|---|---|
| `"abc"` | `string` | `String`, `FixedString(N)`, `Date`, `DateTime`, `UUID`, enums (parsed by CH) |
| `42` / `42.5` | `int64` / `float64` | integer or float types |
| `true` / `false` | `bool` | `Bool`, `UInt8` with implicit cast |
| `null` | `nil` | `Nullable(T)` |
| `[...]` (homogeneous) | `[]T` matching element kind | `Array(T)` |
| `{...}` (object) | — | **reject** (CH `Map`/`Tuple` types are better handled via the SQL text) |

If `coerceParam` sees a type it doesn't know how to bind, return an MCP error result — don't silently drop the parameter.

The driver already accepts `clickhouse.Named(name, value)` alongside positional args; `ExecuteQuery(ctx, query, boundArgs...)` at `:367` needs no changes.

#### Resulting caller ergonomics

**Before:**

```json
{
  "name": "execute_query",
  "arguments": {
    "query": "INSERT INTO claude_otel.dashboards (slug, title, content) VALUES ('weekly-cost', 'Weekly Cost', '<html><body>... 20 KB of HTML with '' doubled and \\\\ doubled ...</body></html>')"
  }
}
```

**After:**

```json
{
  "name": "execute_query",
  "arguments": {
    "query": "INSERT INTO claude_otel.dashboards (slug, title, content) VALUES ({slug:String}, {title:String}, {content:String})",
    "parameters": {
      "slug":    "weekly-cost",
      "title":   "Weekly Cost",
      "content": "<html><body>... 20 KB of HTML with ' and \\ unchanged ...</body></html>"
    }
  }
}
```

The caller writes `content` verbatim. Server binds it as a parameter; ClickHouse receives the bytes untouched.

### Change 3 — Surface parameters in the OpenAPI mirror (`server.go:1975-1990`)

Add a matching `parameters` entry to the OpenAPI path spec so REST/OpenAPI clients get the same affordance:

```go
parameters = append(parameters, map[string]interface{}{
    "name":     "parameters",
    "in":       "query",
    "required": false,
    "description": "JSON-encoded object of named parameters to bind to the query. " +
        "See MCP `execute_query` tool for details.",
    "schema": map[string]interface{}{"type": "string"},
})
```

OpenAPI callers pass `parameters` as a JSON-encoded string (query-string limit still applies, so for truly large values the OpenAPI path is inherently constrained — but for small/medium inputs it helps).

### Change 4 (optional, follow-up PR) — Generic `insert_row` tool

Once parameters work, a much friendlier INSERT shape becomes trivial:

```json
{
  "name": "insert_row",
  "arguments": {
    "table": "claude_otel.dashboards",
    "columns": {
      "slug":    "weekly-cost",
      "title":   "Weekly Cost",
      "content": "<html>..."
    }
  }
}
```

Server composes `INSERT INTO <table> (col1, col2, ...) VALUES ({col1:String}, {col2:String}, ...)` with all values bound as parameters. The server can introspect column types from `system.columns` if it wants to be strict about type coercion, or just trust ClickHouse's implicit casts (usually sufficient).

Benefits over `execute_query`:

- **Discoverable.** Claude picks it by name for INSERTs without having to know SQL syntax details.
- **Smaller payload.** No SQL template travels across the wire.
- **Obviously safe.** The server hardcodes the INSERT shape — no way to accidentally write a DROP.
- **Respects column-level grants.** Bad attempts fail with a clear ClickHouse grant error rather than a half-baked INSERT.

Keep `insert_row` out of the read-only profile's tool list (by inspecting `cfg.ClickHouse.ReadOnly` in RegisterTools). Alternative: register it always and rely on CH to reject — but hiding it reduces Claude's confusion.

Scope note: this is the right *next* PR, not part of the parameterized-query PR. Landing parameters first gives 80% of the value with minimum review surface.

---

## Backward compatibility

- Callers that don't supply `parameters` get byte-identical behaviour to today. No existing integration breaks.
- The `parameters` field is marked optional in the JSON schema; older MCP clients that don't know about it simply ignore it.
- No ClickHouse-side changes.
- Read-only description change is cosmetic (the `ReadOnlyHint` annotation was already correct; LLMs just sometimes over-read the description text).

---

## Implementation pointers

**Files touched:**

| File | Lines (approx) | Change |
|---|---|---|
| `pkg/server/server.go` | 1098-1119 | Extend `execute_query` InputSchema with `parameters` |
| `pkg/server/server.go` | 1744-1800 | Parse `parameters` in `HandleExecuteQuery`, pass as bound args |
| `pkg/server/server.go` | 1110, 1980 | Make the read-only mention conditional on `cfg.ClickHouse.ReadOnly` |
| `pkg/server/server.go` | 1975-1990 | Add `parameters` to the OpenAPI path spec |
| `pkg/clickhouse/client.go` | — | **No changes needed** — existing variadic `args` is already plumbed |
| `pkg/server/server_test.go` | — | New tests (see below) |

**New helper:** `coerceParam(name string, raw any) (any, error)` — 30-40 lines; lives next to `HandleExecuteQuery`. Uses a type switch on the JSON-decoded value. Reject unknown types with a message that names the offending parameter.

**Driver reference:** `clickhouse-go/v2` (already imported; see `pkg/clickhouse/client.go:13`) supports `clickhouse.Named("name", value)` alongside positional placeholders. The driver handles ClickHouse-side `{name:Type}` substitution natively.

---

## Testing

### Unit tests for `coerceParam`

- String → string
- Int-like number → int64 (choose one canonical integer type; CH coerces up)
- Float → float64
- Bool → bool
- Nil → nil
- Array of strings → `[]string`
- Array of mixed types → **reject** with clear error
- Object (JSON `{...}`) → **reject** with clear error
- Nested arrays → reject for v1 (revisit if needed)

### Integration tests against a real CH (via existing `docker-compose` in `pkg/clickhouse/client_test.go`)

Cover the cases that motivate the change:

1. **HTML content with `\"` survives round-trip unchanged.**
   ```sql
   INSERT INTO t (c) VALUES ({c:String})
   -- parameters: {"c": "a\\\"b"}
   -- expect: SELECT c FROM t returns exactly 'a\\"b' (bytes preserved)
   ```

2. **HTML content with `'` survives round-trip unchanged.**
   ```sql
   INSERT INTO t (c) VALUES ({c:String})
   -- parameters: {"c": "it's \"quoted\""}
   ```

3. **Typed binding works for non-String columns.**
   ```sql
   INSERT INTO t (id, created_at) VALUES ({id:UInt64}, {d:DateTime})
   -- parameters: {"id": 42, "d": "2026-04-15 12:34:56"}
   ```

4. **Missing parameter named in SQL produces a clear error.**
   ```sql
   INSERT INTO t (c) VALUES ({missing:String})
   -- parameters: {}
   -- expect: MCP error result naming `missing`
   ```

5. **Extra parameter not named in SQL is silently ignored** (driver behaviour).

6. **SELECT with parameters** returns correct rows.
   ```sql
   SELECT * FROM t WHERE id = {id:UInt64}
   -- parameters: {"id": 42}
   ```

7. **Backward compat — no `parameters` key, existing SQL still works** (add one case to the existing `execute_query` tests).

### Claude.ai / MCP client smoke tests (manual)

- Drive a claude.ai session: ask Claude to INSERT a 15 KB HTML string with `\"` via `execute_query` using parameters. Confirm round-trip bytes match. (Repeats the originally failing case that motivated this proposal.)
- Verify the read-only description says only what the configured mode requires. Flip `clickhouse.read_only` on a test deployment and confirm the description changes in both the MCP tool metadata and the OpenAPI spec.

### Fuzz ideas (if we want to be thorough)

- Random binary strings (all byte values 0-255) through `parameters.content` — confirm byte-exact round-trip. Catches any lingering escape/encoding issue.

---

## Error handling

- `parameters` is not an object → `{type: "text", text: "MCP error: 'parameters' must be a JSON object"}`, `isError: true`.
- Unsupported value type (e.g. nested object) → text error naming the parameter and the unsupported type.
- Named parameter referenced in SQL but missing in `parameters` → bubble up the driver's error verbatim (ClickHouse's own "missing parameter" message is clear enough).
- Read-only mode + write SQL + parameters → the existing read-only gate at `client.go:368` catches it before binding. Unchanged.
- Quota / result-size errors: unchanged.

---

## Out of scope (follow-up)

- Chunked upload tool family (`start_upload` / `append_chunk` / `finish_upload`) — only worth building if the claude.ai per-tool-input cap proves to still bite with `parameters`-style calls. Needs measurement first.
- Anthropic Files API integration (`file_id` parameter values downloaded server-side) — genuinely useful for very large payloads but adds a new auth surface and Anthropic API key dependency. Separate proposal.
- Dynamic tools with parameters already exist (`pkg/server/server.go:1396`, the comment-annotation path); unifying the "typed bind" logic between dynamic and static tools is a nice refactor but not required.
- Support for `Array(Tuple(...))` / nested-type parameters. Driver supports it; schema-level representation is awkward. Defer.

---

## Rollout

Ship Change 1 (read-only description) and Change 2 (parameters on `execute_query`) in one PR. They're self-contained, backward-compatible, and solve the user-visible pain. File a follow-up issue for Change 4 (`insert_row`) once Change 2 has settled. No deprecations, no migration steps.
