# Tools

Altinity MCP Server exposes ClickHouse functionality to MCP clients through **tools**. There are two categories:

- **Static tools** — fixed, registered at startup, always available regardless of ClickHouse state.
- **Dynamic tools** — discovered lazily from ClickHouse (views and tables) on the first authenticated request and surfaced to clients via `notifications/tools/list_changed`.

Both kinds are configured under a single unified key: `server.tools`.

---

## Static tools

Two static tools are built into the server:

| Tool | Description | readOnlyHint | destructiveHint |
|------|-------------|--------------|-----------------|
| `execute_query` | Read-only SQL execution. Rejects any statement that is not `SELECT`, `WITH`, `SHOW`, `DESCRIBE`, `EXISTS`, or `EXPLAIN`. | `true` | `false` |
| `write_query` | Arbitrary SQL (including DDL/DML). Only registered when `clickhouse.read_only: false`. | `false` | `true` |

`execute_query` accepts:

- `query` (string, required) — the SQL to run. Include `LIMIT N` in the SQL itself if you want a specific row cap; the server does not rewrite your query.
- `settings` (object, optional) — ClickHouse query settings forwarded with the request.

`write_query` accepts the same `query` and `settings` parameters and executes the statement as-is.

**Handler mapping:** `name: execute_query` registers the `HandleReadOnlyQuery` function in `pkg/server/server.go`, which enforces the SELECT-only guard and then delegates to `HandleExecuteQuery`. `name: write_query` registers `HandleExecuteQuery` directly. These two names are the only valid values for static tool entries.

### Server-enforced result caps

Operators configure two DoS / context-window guardrails on `execute_query` and on read-mode dynamic tools (SELECT-like queries only — `write_query` and write-mode dynamic tools are unaffected):

| Config key | Default | `0` means | Negative means |
|------------|---------|-----------|----------------|
| `clickhouse.max_result_rows` | 500 | use default | disable (defer to ClickHouse user profile) |
| `clickhouse.max_result_bytes` | 50000 | use default | disable |

The deprecated `clickhouse.limit` is kept as a silent alias for `clickhouse.max_result_rows` — when both are set, `max_result_rows` wins; the legacy key triggers a one-time deprecation warning at startup.

Caps are enforced in two layers: ClickHouse session settings (`max_result_rows`, `max_result_bytes`, `result_overflow_mode='break'`) are pushed per-query so the engine stops early, and the MCP server itself stops appending rows once the configured cap is hit. The row cap is exact; the byte cap is approximate (cheap per-row sizing, not exact JSON byte counts).

When a cap fires, the response carries:

- A `truncated` object inside the JSON `QueryResult` with `reason` (`max_result_rows` or `max_result_bytes`), `limit`, `returned_rows`, and `returned_bytes_approx`.
- For MCP tool responses: a second `text` content block explaining the truncation and recommending narrowing the query (tighter `WHERE`, server-side aggregation, key-range pagination, narrower `SELECT` list). The model should treat the data block as partial until the underlying query is narrowed.
- For OpenAPI REST responses: an `X-MCP-Truncated: max_result_rows` (or `max_result_bytes`) HTTP header alongside the same body field.

---

## Read dynamic tools (Views)

Parameters are declared with ClickHouse's `{name: Type}` placeholder syntax in the view body:

```sql
CREATE VIEW analytics.user_sessions AS
SELECT user_id, session_start, duration_seconds
FROM sessions
WHERE user_id = {user_id: UInt64}
  AND session_start >= {start_date: Date}
  AND session_start <  {end_date: Date}
COMMENT 'Get user sessions for a given date range';
```

The resulting tool exposes `user_id` (integer), `start_date` (string/date), `end_date` (string/date).

### Tool metadata via `COMMENT`

A view's `COMMENT` becomes the tool description. Two forms are supported:

1. **Plain string** — used directly as the description.
2. **Strict JSON object** with any of:
   - `title`
   - `description`
   - `annotations.openWorldHint`

Example:

```sql
CREATE OR REPLACE VIEW mcp.search AS
SELECT number, title
FROM github_events
WHERE title ILIKE '%' || {query: String} || '%'
COMMENT '{"title":"GitHub Search","description":"Returns issues with matching titles.","annotations":{"openWorldHint":true}}';
```

Notes:

- If the comment is not valid JSON, it is treated as a plain description.
- Read dynamic tools are always exposed with `readOnlyHint=true`, `destructiveHint=false`. The JSON form only influences `title`, `description`, and `openWorldHint`.
- Per-parameter metadata in `COMMENT` is not supported yet.
- If no comment is provided, a default title and description are generated.

---

## Write dynamic tools (Tables)

If you need to insert single row to the table, constructing INSERT statement would burn some amount of tokens.  Having a tool is more economical.   

For `type: write` with `mode: insert`, the tool accepts one row at a time. Its parameters are built from `system.columns`:

- Included: columns with `default_kind = ''` (no DEFAULT, MATERIALIZED, EPHEMERAL, or ALIAS).
- Excluded: columns with any default expression.

The tool inserts a single row using the provided values. Bulk or streaming inserts are not supported through this mode.

**Unsupported column types:** Columns with ClickHouse types `Dynamic`, `Array(...)`, `Tuple(...)`, or `JSON`/`JSON(...)` are skipped because these types have no direct JSON Schema equivalent. Such columns do not appear as tool parameters. Use `write_query` to insert values into complex-type columns.

---

## Parameter descriptions

Every dynamic-tool parameter carries a human-readable `description` in its JSON Schema. It is resolved in this order:

1. **Tool-level JSON `COMMENT` with a `params` map** — works for both views and tables. Highest priority.
2. **Column-level `COMMENT` from `system.columns`** — applies to write tools (tables); each column's comment becomes its parameter description.
3. **ClickHouse type string** — final fallback (e.g. `"UInt64"`, `"DateTime"`).

View parameters (`{name: Type}` slots in the SELECT body) aren't real columns, so level 2 doesn't apply to them — use the JSON `COMMENT` `params` map to describe them.

### View example (JSON `params` map is the only source)

```sql
CREATE VIEW analytics.user_sessions AS
SELECT user_id, session_start
FROM sessions
WHERE user_id = {user_id: UInt64}
  AND session_start >= {since: Date}
COMMENT '{
  "description": "Get user sessions for a given date range",
  "params": {
    "user_id": "User ID to fetch",
    "since":   "Start of date range (inclusive)"
  }
}';
```

### Table example (column comments + optional JSON override)

```sql
CREATE TABLE events.clicks (
    user_id UInt64 COMMENT 'User who clicked',
    target  String COMMENT 'URL clicked'
) ENGINE = Log
COMMENT '{
  "params": {
    "target": "Full target URL including query string"
  }
}';
```

Here `user_id` uses its column comment (`"User who clicked"`) and `target` is overridden by the tool-level JSON (`"Full target URL including query string"`). Columns without comments fall back to the ClickHouse type string.

---

## Default behavior (no `tools` config)

If both `server.tools` and the legacy `server.dynamic_tools` are empty, the server registers:

- `execute_query` (always)
- `write_query` (only if `clickhouse.read_only: false`)

No dynamic discovery runs. You only get dynamic tools by adding a `view_regexp` (read) or `table_regexp` (write) entry under `server.tools`.

```yaml
clickhouse:
  host: localhost
  port: 8123
  username: default
  password: ""
# No server.tools block — execute_query (and write_query if not read-only) are auto-registered.
```

---

## Configuring `server.tools`

`server.tools` is a list. Each entry describes one tool (static) or one discovery rule (dynamic):

| Field | Required | Meaning |
|-------|----------|---------|
| `type` | yes | `"read"` or `"write"`. |
| `name` | static only | `"execute_query"` or `"write_query"`. |
| `view_regexp` | dynamic read only | Regex matched against `database.view_name`. Use with `type: read`. |
| `table_regexp` | dynamic write only | Regex matched against `database.table_name`. Use with `type: write`. |
| `prefix` | no | Prepended to auto-generated tool names (dynamic only). |
| `mode` | dynamic write only | Must be `"insert"`. No other value is accepted. |

Rules enforced at config load:

- An entry must have **either** `name` **or** `view_regexp`/`table_regexp`, never both.
- `view_regexp` is only valid with `type: read`; `table_regexp` is only valid with `type: write`.
- A `type: write` entry with `table_regexp` **must** set `mode: insert`.
- Any `mode` value other than `insert` is rejected with an error.
- Invalid regexps are reported at load time and the rule is skipped.
- If a view or table matches multiple rules, that overlap is logged and the later match is skipped.

---

## Example configurations

### Minimal — static tools only

```yaml
clickhouse:
  host: localhost
  port: 8123
  username: default
  password: ""
# server.tools omitted => execute_query (+ write_query if not read-only) registered by default.
```

### Read-only server with view-backed dynamic tools

```yaml
clickhouse:
  host: localhost
  port: 8123
  read_only: true

server:
  tools:
    - type: read
      name: execute_query
    - type: read
      view_regexp: "analytics\\..*_view"
      prefix: "analytics_"
```

Every view in the `analytics` database whose name ends in `_view` is exposed as a read tool named `analytics_<db>_<view>`.

### Mixed read + write dynamic tools

```yaml
server:
  tools:
    - type: read
      name: execute_query
    - type: read
      view_regexp: "analytics\\..*_view"
      prefix: "ro_"
    - type: write
      table_regexp: "events\\..*"
      prefix: "log_"
      mode: insert
```

Views under `analytics` become read tools, tables under `events` become insert-only write tools.

### Legacy `dynamic_tools` (deprecated, still works)

```yaml
server:
  dynamic_tools:
    - regexp: "mydb\\..*"
      prefix: "db_"
```

The server accepts this form but logs a deprecation warning at startup. Prefer `server.tools`.

---

## Dynamic discovery

Discovery is **lazy** — it runs on the first authenticated tool call, not at startup. This matters for OAuth, where ClickHouse credentials can be derived from the user request.

After a successful discovery pass, the server emits `notifications/tools/list_changed` so compatible MCP clients refresh their tool list.

If discovery fails (e.g. credential error, network issue), static tools remain available and discovery is retried on the next authenticated call.

### What gets discovered

- **Read tools** — rows in `system.tables` with `engine = 'View'`. Parameters are parsed from `create_table_query` using the `{param_name: Type}` syntax.
- **Write tools** (`mode: insert`) — rows in `system.tables` of any engine. Column metadata comes from `system.columns`; only columns where `default_kind = ''` (no default) are surfaced as required parameters. Columns with defaults are omitted from the tool schema.

### Credentials used for discovery

| Auth | Credentials used |
|------|------------------|
| JWE | The per-request JWE token from the triggering call. |
| OAuth | The Bearer token from the triggering call. |
| Plain / no auth | Static `clickhouse.username` / `clickhouse.password` from config, if set. |

Static credentials are no longer **required** for discovery in JWE or OAuth setups — whichever token arrives with the first authenticated call is used to probe `system.tables`.

---

## Type mapping

ClickHouse types are mapped to JSON Schema as follows:

| ClickHouse type | JSON type | JSON format |
|-----------------|-----------|-------------|
| `Int*`, `UInt*` | `integer` | `int64` |
| `Float*`, `Decimal*` | `number` | `double` |
| `Bool`, `UInt8` (boolean-ish) | `boolean` | — |
| `Date`, `Date32` | `string` | `date` |
| `DateTime*` | `string` | `date-time` |
| `UUID` | `string` | `uuid` |
| Anything else | `string` | — |

**Unsupported types for write tools:** `Dynamic`, `Array(...)`, `Tuple(...)`, and `JSON`/`JSON(...)` columns are skipped entirely — they have no JSON Schema equivalent and are excluded from the tool's parameter list. Use `write_query` to insert into such columns.

---

## Tool name generation

For dynamic entries (have `view_regexp` or `table_regexp`, no `name`), the tool name is:

```
snake_case(prefix + database + "_" + view_or_table_name)
```

`snake_case` lowercases the input and replaces any run of non-alphanumerics with `_`.

Examples:

| Prefix | Matched object | Generated tool name |
|--------|----------------|---------------------|
| `ro_` | `analytics.user_sessions` | `ro_analytics_user_sessions` |
| `log_` | `events.clicks` | `log_events_clicks` |
| _(none)_ | `mydb.users` | `mydb_users` |

---

## MCP safety hints

Altinity MCP sets MCP tool annotations (the OpenAI Apps SDK tool-safety hints) so
compatible clients can gauge each tool's risk and skip unnecessary confirmation
prompts:

- **`readOnlyHint`** — `true` for tools that only read, retrieve, or compute and
  never create, update, delete, or send data outside the client.
- **`destructiveHint`** — `true` for tools that can delete, overwrite, or
  otherwise cause irreversible side effects. Only meaningful when
  `readOnlyHint=false`.
- **`openWorldHint`** — `true` for tools that write to arbitrary/unbounded
  external targets (URLs, files, etc.); `false` for bounded writes to known
  resources. Altinity MCP only ever touches ClickHouse, so this is `false` by
  default. Only meaningful when `readOnlyHint=false`.

| Tool kind | `readOnlyHint` | `destructiveHint` | `openWorldHint` |
|-----------|----------------|-------------------|-----------------|
| `execute_query` | `true` | `false` | `false` |
| Dynamic read (view) | `true` | `false` | `false` |
| `write_query` | `false` | `true` | `false` |
| Dynamic write (`insert`) | `false` | `false` | `false` |

Any of these can be overridden per dynamic tool via the view/table `COMMENT`
JSON `annotations` object (see [Tool metadata via `COMMENT`](#tool-metadata-via-comment)) —
e.g. a view that fans out to an external API can set `openWorldHint: true`.

References:

- [Apps SDK Reference](https://developers.openai.com/apps-sdk/reference)
- [Define tools](https://developers.openai.com/apps-sdk/plan/tools)
- [Build your MCP server](https://developers.openai.com/apps-sdk/build/mcp-server)
- [MCP concepts / server docs](https://developers.openai.com/apps-sdk/concepts/mcp-server)
- [MCP `ToolAnnotations` schema](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations)

---

## OpenAPI integration

When `server.openapi.enabled: true`, every registered tool — static and dynamic — also gets:

- A `POST` endpoint at `/{jwe_token}/openapi/{tool_name}` (or the non-JWE variant in other auth modes).
- A request body schema derived from the tool's parameters.
- A response schema matching the query result shape.

Because dynamic discovery is lazy, dynamic tools only appear in the OpenAPI document **after** the first authenticated call has triggered discovery.

---

## Troubleshooting

### Dynamic tools don't show up immediately after the server starts

Expected. Discovery runs on the first authenticated tool call, not at startup. Make one call (e.g. `execute_query`) and clients that honor `notifications/tools/list_changed` will refresh to show the new dynamic tools. Clients that don't honor the notification need to re-list tools manually.

### A view or table isn't being exposed

1. Confirm the object exists in `system.tables` (with `engine = 'View'` for read tools).
2. Check that your `view_regexp` / `table_regexp` matches `database.name` — remember to escape the dot (`\\.`).
3. Look for overlap warnings: if multiple rules match the same object, the later one is skipped.
4. For write tools, verify you set `mode: insert` and `type: write`.

### Parameters aren't detected on a view

1. Use the exact syntax `{param_name: Type}` inside the view body.
2. Parameter names must be valid identifiers.
3. Confirm the server can read `system.tables.create_table_query` for that view.

### Write tool is missing expected columns

Columns with defaults (`DEFAULT`, `MATERIALIZED`, `EPHEMERAL`, `ALIAS`) are intentionally omitted from the tool schema — they are filled in by ClickHouse. Only columns with `default_kind = ''` appear as parameters.

### Discovery keeps failing

Each failed attempt is logged and retried on the next authenticated call. Common causes:

- The token (JWE or Bearer) carries credentials that can't read `system.tables` / `system.columns`.
- The configured `clickhouse.host` / `port` aren't reachable from the server.
- A `view_regexp` or `table_regexp` is invalid — check startup logs for `invalid regexp, skipping rule`.

Static tools (`execute_query`, `write_query`) continue to work even while discovery is failing.

### `mode` validation error at startup

```
server.tools: write tool with table_regexp requires mode: insert
```

Add `mode: insert` to the offending write entry. Any other `mode` value is rejected.
test
