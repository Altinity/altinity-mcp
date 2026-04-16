# Testing Guide: Issue #35 Implementation

## Quick Verification

### 1. Compilation Check

```bash
# From project root
go build ./cmd/altinity-mcp

# Should complete without errors
```

### 2. Configuration Syntax

**Test 1: Unified Config (New Format)**

```yaml
# config.yaml
clickhouse:
  host: localhost
  port: 8123
  database: default
  username: default
  password: ""
  protocol: http

server:
  transport: stdio
  
  # NEW: Unified tools array
  tools:
    # Static tools
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    # Dynamic read tools from views
    - type: "read"
      regexp: "^test\\..*_view$"
      prefix: "view_"
    
    # Dynamic write tools from tables
    - type: "write"
      regexp: "^test\\..*_table$"
      prefix: "write_"
      mode: "insert"
```

**Test 2: Backwards Compat (Old Format)**

```yaml
server:
  transport: stdio
  
  # OLD: Dynamic tools only (should still work with deprecation warning)
  dynamic_tools:
    - regexp: "test\\..*_view"
      prefix: "legacy_"
```

### 3. Runtime Tests

**Setup**: Create test views and tables in ClickHouse

```sql
-- Create test database
CREATE DATABASE IF NOT EXISTS test;

-- Create test view for read tool discovery
CREATE VIEW test.users_view AS
SELECT 1 as id, 'John' as name;

-- Create test table for write tool discovery
CREATE TABLE test.events_table (
  id Int64,
  event_type String,
  timestamp DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY (timestamp, id);
```

**Test 3: Tool Discovery**

Start server with test config:
```bash
./altinity-mcp --config config.yaml
```

Check logs for:
- ✅ "ClickHouse tools registered" (static tools)
- ✅ "Dynamic read tools discovered" (from views)
- ✅ "Dynamic write tools discovered" (from tables)

### 4. Read-Only Mode Test

```yaml
clickhouse:
  host: localhost
  port: 8123
  database: default
  read_only: true  # <-- Read-only mode
  # ...

server:
  tools:
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    - type: "write"
      regexp: "^test\\..*_table$"
      prefix: "write_"
      mode: "insert"
```

**Expected Result**:
- ✅ `execute_query` registered
- ✅ `write_query` skipped (log: "Write tool skipped (read-only mode)")
- ✅ Write tools skipped (log: "Write tools disabled in read-only mode")

### 5. Tool Hiding Test

**Config**: Hide generic `write_query`, use only dynamic tools

```yaml
server:
  tools:
    - type: "read"
      name: "execute_query"
    
    # NO write_query entry here!
    
    - type: "write"
      regexp: "^test\\..*_table$"
      prefix: "insert_"
      mode: "insert"
```

**Expected Result**:
- ✅ Tools: `execute_query`, `insert_*` (from tables)
- ❌ Generic `write_query` not available

### 6. Column Filtering Test

**Setup**: Create table with various column types

```sql
CREATE TABLE test.column_test (
  id Int64,                              -- Normal column
  name String DEFAULT 'unknown',        -- With default
  computed_value Int64 MATERIALIZED id * 2,  -- Materialized (should be excluded)
  alias_col String ALIAS name,          -- Alias (should be excluded)
  timestamp DateTime DEFAULT now()       -- With default
) ENGINE = MergeTree ORDER BY id;
```

**Expected Tool Parameters** (insert mode):
- ✅ `id` (required)
- ✅ `name` (optional, has default)
- ✅ `timestamp` (optional, has default)
- ❌ `computed_value` (materialized - excluded)
- ❌ `alias_col` (alias - excluded)

Check tool schema via:
```bash
# The tool's InputSchema should only list id, name, timestamp
# In OpenAPI: GET /{tool_name}/schema
```

### 7. INSERT Query Generation Test

**Tool**: `insert_column_test` (from `test.column_test`)

**Test Call** (mock):
```json
{
  "id": 123,
  "name": "Alice"
}
```

**Expected Query**:
```sql
INSERT INTO test.column_test (id, name) VALUES (123, 'Alice')
```

**Expected Result**:
- ✅ Query executed
- ✅ Row inserted into table

### 8. Error Handling Test

**Test Case**: Missing required parameter

```json
{
  "name": "Bob"
}
```

**Expected Result**:
- ❌ Error: "required parameter missing: id"
- ✅ Query NOT executed
- ✅ Clear error message to user

**Test Case**: UPDATE mode (not yet implemented)

```yaml
server:
  tools:
    - type: "write"
      regexp: "^test\\..*_table$"
      prefix: "update_"
      mode: "update"  # <-- UPDATE mode
```

**Expected Result**:
- ⚠️ Tool registered
- ❌ Error on call: "UPDATE mode not yet implemented; use write_query tool instead"

### 9. Backwards Compatibility Test

**Setup**: Use old `dynamic_tools` config

```yaml
server:
  dynamic_tools:
    - regexp: "test\\..*_view"
      prefix: "legacy_"
```

**Expected Result**:
- ⚠️ Deprecation warning: "dynamic_tools config is deprecated, use tools instead"
- ✅ Tools still discovered and registered
- ✅ Functionally identical to new config

### 10. Default Behavior Test

**Config**: No tools section at all

```yaml
server:
  transport: stdio
  # No 'tools' field
```

**Expected Result**:
- ✅ `execute_query` tool registered (default)
- ✅ `write_query` tool registered (default)
- No dynamic tools

## Integration Test Checklist

- [ ] Compile without errors
- [ ] Read-only mode prevents write tool registration
- [ ] Dynamic read tools discovered from views
- [ ] Dynamic write tools discovered from tables
- [ ] Column filtering excludes alias/materialized/virtual
- [ ] INSERT query generation works correctly
- [ ] Required parameters validated
- [ ] Optional parameters handled (with defaults)
- [ ] SQL escaping works (special characters in strings)
- [ ] Backward compat: old dynamic_tools config works
- [ ] Tool annotations correct (ReadOnlyHint, DestructiveHint)
- [ ] Error messages clear and helpful

## Performance Tests

- [ ] Tool discovery completes quickly (< 1 second)
- [ ] No memory leaks on repeated calls
- [ ] Large tables (100+ columns) handled correctly

## Edge Cases

### Extreme Schema

```sql
CREATE TABLE test.wide_table (
  col1 String, col2 String, col3 String, -- ...
  col100 String
) ENGINE = MergeTree ORDER BY col1;
```

- [ ] Discovery handles table with 100+ columns
- [ ] INSERT parameter generation works
- [ ] No performance degradation

### Special Characters in Table Names

```sql
CREATE TABLE test.`table-with-dashes` (id Int64) ENGINE = MergeTree ORDER BY id;
```

- [ ] Discovery works with special characters
- [ ] Tool names sanitized correctly
- [ ] Queries execute properly

### SQL Injection Attempts

**Tool call with malicious input**:
```json
{
  "name": "'; DROP TABLE test.events_table; --"
}
```

- ❌ Should NOT execute DROP
- ✅ Should use parameterized/escaped query
- ✅ Data safely inserted (with escaped quotes)

## Manual Testing Commands

### Start Server
```bash
./altinity-mcp \
  --config config.yaml \
  --log-level debug
```

### Test with MCP Client
```bash
# List tools
mcp list-tools

# Check tool schema
mcp get-tool-schema execute_query
mcp get-tool-schema write_*

# Call read tool
mcp call-tool execute_query \
  --query "SELECT 1 as test"

# Call write tool
mcp call-tool insert_events_table \
  --event_type "user_login" 
```

## Debugging

### Enable Debug Logging
```yaml
logging:
  level: debug
```

### Check Tool Discovery
Look for these logs:
- "Dynamic read tools discovered" - tools from views
- "Dynamic write tools discovered" - tools from tables
- "Dynamic tools registered" - final count
- "Tool definitions:" - detailed list

### Verify Column Filtering
```sql
-- Check what columns are seen
SELECT name, column_type, default_kind 
FROM system.columns 
WHERE database='test' AND table='events_table'
ORDER BY position;
```

Expected excludes:
- Columns with `column_type` = 'alias', 'materialized', 'virtual'
- Columns with `default_kind` = 'MATERIALIZED', 'ALIAS'

## Success Criteria

Implementation is considered complete when:

1. ✅ Code compiles without errors
2. ✅ Static tools (`execute_query`, `write_query`) register correctly
3. ✅ Dynamic tools discovered from views and tables
4. ✅ Column filtering works (excludes alias/materialized/virtual)
5. ✅ INSERT queries generated correctly with parameters
6. ✅ Required parameters validated
7. ✅ Read-only mode prevents write tools
8. ✅ Old `dynamic_tools` config still works (backwards compat)
9. ✅ Tool annotations correct (destructive hint for write tools)
10. ✅ Error messages clear and helpful
