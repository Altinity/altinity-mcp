# Dynamic Tools

Dynamic tools in Altinity MCP Server allow you to automatically generate MCP tools from ClickHouse views. This feature enables you to expose parameterized views as callable tools through the MCP interface.

## Overview

Dynamic tools are configured in the `server.dynamic_tools` section of the configuration file. The server will query `system.tables` for views and create corresponding MCP tools based on the rules you define.

## Configuration

Each dynamic tool rule consists of three optional fields:

- **`name`** (optional): The explicit name for the generated tool. When specified, the regexp must match exactly one view from `system.tables`. If not specified, the tool name is generated from the matched view name.
- **`regexp`** (required): A regular expression pattern to match against view names in the format `database.view_name`.
- **`prefix`** (optional): A prefix to prepend to the tool name (applied before name generation or to the explicit name).

### Basic Configuration

```yaml
server:
  dynamic_tools:
    - regexp: "mydb\\..*"
      prefix: "db_"
```

This configuration will:
- Match all views in the `mydb` database
- Generate tool names like `db_mydb_my_view` for each matched view

### Named Tool Configuration

```yaml
server:
  dynamic_tools:
    - name: "get_user_data"
      regexp: "users\\.user_info_view"
      prefix: "api_"
```

This configuration will:
- Match exactly one view: `users.user_info_view`
- Create a tool named `api_get_user_data`
- Log an error if the regexp matches zero or multiple views

### Mixed Configuration

You can combine both approaches:

```yaml
server:
  dynamic_tools:
    # Generate tools for all views in analytics database
    - regexp: "analytics\\..*"
      prefix: "analytics_"

    # Specific tool with custom name
    - name: "get_current_metrics"
      regexp: "monitoring\\.current_metrics_view"

    # Another specific tool with prefix
    - name: "user_report"
      regexp: "reports\\.user_activity"
      prefix: "report_"
```

## View Parameters

Dynamic tools automatically detect parameters in your ClickHouse view definitions. Parameters are defined using the `{parameter_name: type}` syntax in the view's SQL.

### Example View with Parameters

```sql
CREATE VIEW analytics.user_sessions AS
SELECT
    user_id,
    session_start,
    session_end,
    duration_seconds
FROM sessions
WHERE user_id = {user_id: UInt64}
  AND session_start >= {start_date: Date}
  AND session_start < {end_date: Date}
COMMENT 'Get user session data for a specific date range'
```

This view will generate a tool with three parameters:
- `user_id` (number/integer)
- `start_date` (string/date)
- `end_date` (string/date)

The view's `COMMENT` will be used as the tool's description. If no comment is provided, a default description is generated.

### Rich Descriptions with JSON

You can provide richer descriptions for both the tool and its parameters by using a JSON object in the view's comment. The format is:

```json
{
  "database.view_name:description": "Main tool description",
  "param1": "Description for param1",
  "param2": "Description for param2"
}
```

Example:

```sql
CREATE VIEW analytics.user_sessions AS
SELECT ...
COMMENT '{"analytics.user_sessions:description": "Get user session data", "user_id": "The user ID to filter by", "start_date": "Start of the period"}'
```

If the comment is not valid JSON, it is treated as a plain string description for the tool.

When a parameter description is provided via JSON, it is appended to the ClickHouse type in the tool's parameter description (e.g., "UInt64, The user ID to filter by").

## Type Mapping

ClickHouse types are automatically mapped to JSON Schema types for the MCP tool interface:

| ClickHouse Type | JSON Type | JSON Format |
|----------------|-----------|-------------|
| Int*, UInt*    | integer   | int64       |
| Float*, Decimal* | number  | double      |
| Bool, UInt8    | boolean   | -           |
| Date, Date32   | string    | date        |
| DateTime*      | string    | date-time   |
| UUID           | string    | uuid        |
| Other types    | string    | -           |

## Tool Name Generation

Tool names are generated using the following rules:

1. If `name` is specified: `snake_case(prefix + name)`
2. If `name` is not specified: `snake_case(prefix + database.view_name)`

The `snake_case` function converts the name to lowercase and replaces non-alphanumeric characters with underscores.

### Examples

| Name | Regexp | Prefix | Matched View | Generated Tool Name |
|------|--------|--------|--------------|---------------------|
| - | `mydb\\.my_view` | `api_` | `mydb.my_view` | `api_mydb_my_view` |
| `get_data` | `mydb\\.my_view` | `api_` | `mydb.my_view` | `api_get_data` |
| `get_data` | `mydb\\.my_view` | - | `mydb.my_view` | `get_data` |
| - | `mydb\\..*` | - | `mydb.users` | `mydb_users` |

## Validation Rules

The dynamic tools system enforces several validation rules:

1. **Regexp Validity**: All regular expressions must be valid. Invalid patterns are logged as errors and skipped.

2. **No Overlaps**: Each view can only be matched by one rule. If a view matches multiple rules, it will be logged as an error and skipped.

3. **Named Rules Must Match Exactly Once**: When a rule specifies a `name`, the `regexp` must match exactly one view from `system.tables`. The system will log an error if:
   - The regexp matches zero views
   - The regexp matches more than one view

4. **View Requirements**: Only views with `engine='View'` are considered for dynamic tool generation.

## Error Handling

The dynamic tools system logs errors in the following cases:

- **Invalid regexp**: `dynamic_tools: invalid regexp, skipping rule`
- **Overlap detected**: `dynamic_tools: overlap between rules detected for view`
- **Named rule matches zero views**: `dynamic_tools: named rule matched no views`
- **Named rule matches multiple views**: `dynamic_tools: named rule matched multiple views, expected exactly one`

These errors are logged but do not prevent the server from starting. Valid rules will still be processed.

## Complete Example

```yaml
clickhouse:
  host: localhost
  port: 8123
  database: default
  username: default
  password: ""
  protocol: http

server:
  transport: http
  address: 0.0.0.0
  port: 8080
  openapi:
    enabled: true
  dynamic_tools:
    # Match all views in analytics database
    - regexp: "analytics\\..*"
      prefix: "analytics_"

    # Specific tool for user data
    - name: "get_user_info"
      regexp: "users\\.user_info_view"
      prefix: "api_"

    # Specific tool for metrics (no prefix)
    - name: "current_metrics"
      regexp: "monitoring\\.metrics_view"

logging:
  level: info
```

## OpenAPI Integration

Dynamic tools are automatically exposed through the OpenAPI endpoints when `server.openapi.enabled` is set to `true`. Each tool gets:

- A POST endpoint at `/{jwe_token}/openapi/{tool_name}`
- Request body schema based on the view parameters
- Response schema for the query results

## Best Practices

1. **Use descriptive names**: When using the `name` field, choose clear, descriptive names that indicate the tool's purpose.

2. **Add comments to views**: Use the `COMMENT` clause in your view definitions to provide meaningful descriptions for the generated tools.

3. **Use specific regexps**: For named tools, use specific regular expressions to ensure only one view matches.

4. **Organize by database**: Group related views in the same database and use regexp patterns to generate tools for entire databases.

5. **Test your regexps**: Before deploying, test your regular expressions to ensure they match the intended views.

6. **Monitor logs**: Check the server logs during startup to catch any validation errors or misconfigurations.

## Troubleshooting

### Tool not being generated

1. Check that the view exists in `system.tables` with `engine='View'`
2. Verify the regexp pattern matches the view name in the format `database.view_name`
3. Check for overlap errors in the logs

### Named tool reports "matched no views"

1. Verify the view name format is `database.view_name`
2. Check that the view exists in ClickHouse
3. Ensure the regexp pattern correctly escapes special characters (e.g., `\\.` for dots)

### Named tool reports "matched multiple views"

1. Make the regexp more specific to match only one view
2. Consider using a different approach or splitting into multiple rules

### Parameters not detected

1. Ensure parameters are defined using the correct syntax: `{param_name: Type}`
2. Check that the parameter names are valid identifiers (letters, numbers, underscores)
3. Verify the view's `CREATE` statement is accessible in `system.tables.create_table_query`
