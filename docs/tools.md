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

- `query` (string, required) — the SQL to run.
- `limit` (integer, optional) — caps returned rows.
- `settings` (object, optional) — ClickHouse query settings forwarded with the request.

`write_query` accepts the same `query` and `settings` parameters and executes the statement as-is.

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

For `type: write` with `mode: insert`, the tool accepts one row at a time. Its parameters are built from `system.columns`:

- Included: columns with `default_kind = ''` (no DEFAULT, MATERIALIZED, EPHEMERAL, or ALIAS).
- Excluded: columns with any default expression.

The tool inserts a single row using the provided values. Bulk or streaming inserts are not supported through this mode.

---

## Default behavior (no `tools` config)

If both `server.tools` and the legacy `server.dynamic_tools` are empty, the server registers:

- `execute_query` (always)
- `write_query` (only if `clickhouse.read_only: false`)

No dynamic discovery runs. You only get dynamic tools by adding a `regexp` entry under `server.tools`.

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
| `regexp` | dynamic only | Regex matched against `database.table_or_view_name`. |
| `prefix` | no | Prepended to auto-generated tool names (dynamic only). |
| `mode` | dynamic write only | Must be `"insert"`. No other value is accepted. |

Rules enforced at config load:

- An entry must have **either** `name` **or** `regexp`, never both.
- A `type: write` entry with `regexp` **must** set `mode: insert`.
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
      regexp: "analytics\\..*_view"
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
      regexp: "analytics\\..*_view"
      prefix: "ro_"
    - type: write
      regexp: "events\\..*"
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

Discovery is **lazy** — it runs on the first authenticated tool call, not at startup. This matters for OAuth forward mode, where no ClickHouse credentials exist until a user request arrives.

After a successful discovery pass, the server emits `notifications/tools/list_changed` so compatible MCP clients refresh their tool list.

If discovery fails (e.g. credential error, network issue), static tools remain available and discovery is retried on the next authenticated call.

### What gets discovered

- **Read tools** — rows in `system.tables` with `engine = 'View'`. Parameters are parsed from `create_table_query` using the `{param_name: Type}` syntax.
- **Write tools** (`mode: insert`) — rows in `system.tables` of any engine. Column metadata comes from `system.columns`; only columns where `default_kind = ''` (no default) are surfaced as required parameters. Columns with defaults are omitted from the tool schema.

### Credentials used for discovery

| Auth mode | Credentials used |
|-----------|------------------|
| JWE | The per-request JWE token from the triggering call. |
| OAuth forward | The forwarded Bearer token from the triggering call. |
| Plain / no auth | Static `clickhouse.username` / `clickhouse.password` from config, if set. |

Static credentials are no longer **required** for discovery in JWE or OAuth-forward setups — whichever token arrives with the first authenticated call is used to probe `system.tables`.

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

---

## Tool name generation

For dynamic entries (have `regexp`, no `name`), the tool name is:

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

| Tool kind | `readOnlyHint` | `destructiveHint` |
|-----------|----------------|-------------------|
| `execute_query` | `true` | `false` |
| Dynamic read (view) | `true` | `false` |
| `write_query` | `false` | `true` |
| Dynamic write (`insert`) | `false` | `false` |

These hints follow the OpenAI Apps SDK tool-annotation guidance and reduce unnecessary confirmation prompts in compatible clients.

References:

- [Apps SDK Reference](https://developers.openai.com/apps-sdk/reference)
- [Define tools](https://developers.openai.com/apps-sdk/plan/tools)
- [Build your MCP server](https://developers.openai.com/apps-sdk/build/mcp-server)
- [MCP concepts / server docs](https://developers.openai.com/apps-sdk/concepts/mcp-server)

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
2. Check that your `regexp` matches `database.name` — remember to escape the dot (`\\.`).
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
- A `regexp` is invalid — check startup logs for `invalid regexp, skipping rule`.

Static tools (`execute_query`, `write_query`) continue to work even while discovery is failing.

### `mode` validation error at startup

```
server.tools: write tool with regexp requires mode: insert
```

Add `mode: insert` to the offending write entry. Any other `mode` value is rejected.
test
