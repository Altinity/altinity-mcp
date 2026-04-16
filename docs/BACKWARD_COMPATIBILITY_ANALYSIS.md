# Backward Compatibility Analysis - Issue #35

## Executive Summary

**Status**: ✅ Full backward compatibility maintained

When `server.tools` is **not defined** in the configuration:
1. **Default tools are registered**: `execute_query` + `write_query`
2. **Tools ARE announced**: Full MCP tool metadata is provided
3. **Behavior is identical** to old config format

---

## How It Works Without `server.tools`

### Configuration Scenarios

#### Scenario 1: No `tools` at all (Minimal Config)

```yaml
server:
  transport: stdio
  # No 'tools' field
  # No 'dynamic_tools' field
```

**What happens:**
```
RegisterTools() → No server.tools → No server.dynamic_tools → Use defaults
```

**Tools registered:**
- ✅ `execute_query` (read-only, always safe)
- ✅ `write_query` (unless read_only: true)

**Code location**: `pkg/server/server.go:1125-1131`
```go
} else {
    // Default: register static tools only
    toolsToRegister = []config.ToolDefinition{
        {Type: "read", Name: "execute_query"},
        {Type: "write", Name: "write_query"},
    }
}
```

#### Scenario 2: Old `dynamic_tools` format (Legacy)

```yaml
server:
  dynamic_tools:
    - regexp: "^analytics\\..*_view$"
      prefix: "analytics_"
```

**What happens:**
```
RegisterTools() → No server.tools → Has server.dynamic_tools → Convert + Log warning
```

**Tools registered:**
- ✅ `execute_query` (default static tool)
- ✅ `write_query` (default static tool)
- ✅ `analytics_*` (discovered dynamic tools from views)

**Log message:**
```
WARN dynamic_tools config is deprecated, use tools instead
```

**Code location**: `pkg/server/server.go:1108-1124`
```go
} else if len(cfg.Server.DynamicTools) > 0 {
    // Old format: convert DynamicTools to ToolDefinition for backwards compatibility
    log.Warn().Msg("dynamic_tools config is deprecated, use tools instead")
    for _, oldRule := range cfg.Server.DynamicTools {
        toolDef := config.ToolDefinition{
            Type:   oldRule.Type,
            Name:   oldRule.Name,
            Regexp: oldRule.Regexp,
            Prefix: oldRule.Prefix,
            Mode:   oldRule.Mode,
        }
        // Default type to "read" if not specified (backwards compat)
        if toolDef.Type == "" && toolDef.Regexp != "" {
            toolDef.Type = "read"
        }
        toolsToRegister = append(toolsToRegister, toolDef)
    }
}
```

---

## Tool Announcement Details

### What "Announced" Means

When tools are "announced", the MCP server:
1. Calls `srv.AddTool(tool, handler)` to register the tool
2. Provides full metadata including:
   - Tool name
   - Title/description
   - Input schema (parameters)
   - Annotations (safety hints)
   - Handler function

The MCP client (Claude, other tools) can then:
- See the tool in the `tools/list` response
- Understand what it does
- Know its safety properties
- Call it with proper parameters

### Default Tools Announcement

Both default tools are fully announced with complete metadata:

#### `execute_query` Tool

```
Name: execute_query
Title: "Execute SQL Query"
Description: "Executes a SQL query against ClickHouse and returns the results"

Input Schema:
  - query (required): SQL query string
  - limit (optional): Max rows to return

Annotations:
  ReadOnlyHint: false (or true if read_only mode)
  DestructiveHint: true (in non-read-only mode)
  OpenWorldHint: false
```

**Code location**: `pkg/server/server.go:1173-1195`

#### `write_query` Tool

```
Name: write_query
Title: "Execute Write Query"
Description: "Executes a write query (INSERT, UPDATE, DELETE, ALTER) against ClickHouse"

Input Schema:
  - query (required): SQL write query string
  - limit (optional): Max rows for result sets

Annotations:
  ReadOnlyHint: false
  DestructiveHint: true ← Explicitly marked as destructive
  OpenWorldHint: false
```

**Code location**: `pkg/server/server.go:1206-1230`

---

## Behavior Comparison

### Old Config (Before Issue #35)

```yaml
server:
  transport: stdio
  dynamic_tools:
    - regexp: "^test\\..*_view$"
      prefix: "view_"
```

**Result:**
- `execute_query` + `write_query` (defaults)
- `view_*` tools (dynamic from views)

---

### New Config (After Issue #35)

**Option A: Minimal (No config)**
```yaml
server:
  transport: stdio
```

**Result:**
- `execute_query` + `write_query` (defaults)
- No dynamic tools

---

**Option B: Explicit (New format)**
```yaml
server:
  tools:
    - type: "read"
      name: "execute_query"
    - type: "write"
      name: "write_query"
    - type: "read"
      regexp: "^test\\..*_view$"
      prefix: "view_"
```

**Result:**
- `execute_query` + `write_query` (static)
- `view_*` tools (dynamic from views)

---

**Option C: Selective (Hide write_query)**
```yaml
server:
  tools:
    - type: "read"
      name: "execute_query"
    - type: "write"
      regexp: "^test\\..*_table$"
      prefix: "insert_"
      mode: "insert"
```

**Result:**
- `execute_query` (static)
- `insert_*` tools (dynamic from tables)
- **No `write_query`** ← Hidden!

---

## Edge Cases

### Case 1: Read-Only Mode Without Config

```yaml
clickhouse:
  read_only: true

server:
  transport: stdio
  # No tools config
```

**Tools announced:**
- ✅ `execute_query` (ReadOnlyHint: true, safe)
- ❌ `write_query` **NOT registered** (skipped due to read_only mode)

**Code location**: `pkg/server/server.go:1202-1205`
```go
if readOnly {
    log.Info().Str("tool", "write_query").Msg("Write tool skipped (read-only mode)")
    return
}
```

**Log output:**
```
INFO  Static read tool registered tool=execute_query
INFO  Write tool skipped (read-only mode) tool=write_query
```

---

### Case 2: Empty Dynamic Tools

```yaml
server:
  dynamic_tools: []  # Empty array
```

**Behavior:**
```
RegisterTools() → No server.tools → Empty server.dynamic_tools → Use defaults
```

**Tools announced:**
- ✅ `execute_query` + `write_query` (defaults)
- No dynamic tools discovered

---

### Case 3: Mixed Config (Should Not Happen But Handled)

```yaml
server:
  tools:
    - type: "read"
      name: "execute_query"
  dynamic_tools:
    - regexp: "^analytics\\..*_view$"
      prefix: "get_"
```

**Behavior:**
```
RegisterTools() → Has server.tools → Use only server.tools (ignore dynamic_tools)
```

**Tools announced:**
- ✅ `execute_query` only
- `dynamic_tools` config ignored (not processed)

**Why:** New config takes precedence (line 1105-1107):
```go
if len(cfg.Server.Tools) > 0 {
    // New unified tools config
    toolsToRegister = cfg.Server.Tools
    // ... dynamic_tools not checked
}
```

---

## Dynamic Tool Discovery

### When Do Dynamic Tools Get Discovered?

Dynamic tools are discovered **lazily** on first use:

1. **RegisterTools()** (startup):
   - Registers static tools
   - Stores dynamic tool rules in `cfg.Server.DynamicTools`

2. **EnsureDynamicTools()** (lazy, on first tool call):
   - Checks if dynamic tool rules exist
   - If none → returns immediately, no discovery
   - If rules exist → discovers and registers tools

**Code location**: `pkg/server/server.go:1421-1424`
```go
if len(s.Config.Server.DynamicTools) == 0 {
    s.dynamicToolsInit = true
    return nil  // No dynamic tools, nothing to do
}
```

### What Gets Discovered?

- **Read tools**: Views matching `regexp` patterns
- **Write tools**: Tables matching `regexp` patterns
  - Excludes system tables
  - Excludes alias/materialized/virtual columns

### Example: No Config

```
Config: { }
         ↓
RegisterTools() registers: execute_query, write_query
                          ↓
         DynamicTools = []
         ↓
EnsureDynamicTools() → No rules → Returns immediately
                      ↓
         No dynamic tools discovered
         ↓
MCP client sees: execute_query, write_query only
```

---

## Tool Metadata & Annotations

### Annotations Explain Tool Safety

The MCP spec defines safety annotations so clients (Claude, OpenAI) know:
- **ReadOnlyHint**: Can this tool modify data?
- **DestructiveHint**: Can this tool delete/drop data?
- **OpenWorldHint**: Does this tool have unpredictable effects?

### Default Tools Annotations

| Tool | ReadOnlyHint | DestructiveHint | OpenWorldHint |
|------|--------------|-----------------|---------------|
| `execute_query` (normal) | false | **true** | false |
| `execute_query` (read-only mode) | **true** | false | false |
| `write_query` | false | **true** | false |
| `insert_*` (dynamic) | false | **true** | false |
| `view_*` (dynamic) | **true** | false | false |

**Why execute_query is marked destructive in normal mode:**
- It accepts arbitrary SQL
- Could be SELECT or DROP
- Client needs to know it's not safe

**When read-only mode is ON:**
- `execute_query` marked as safe (ReadOnlyHint: true)
- `write_query` not registered at all
- No dynamic write tools registered

---

## Summary: What Happens Without `server.tools`

| Configuration State | Static Tools | Dynamic Tools | Read-Only Mode |
|-------------------|--------------|---------------|-----------------|
| No config at all | execute_query, write_query | None | execute_query only |
| Empty `dynamic_tools: []` | execute_query, write_query | None | execute_query only |
| Old `dynamic_tools: [...]` | execute_query, write_query | Discovered (with warning) | execute_query only |
| New `server.tools: [...]` | Configured | Configured | Based on read_only |

**In all cases**: Tools are fully announced with metadata. MCP client has all information.

---

## Migration Path (Old → New Config)

### Before Issue #35
```yaml
server:
  dynamic_tools:
    - regexp: "^analytics\\..*_view$"
      prefix: "analytics_"
```

### After Issue #35 (Option 1: Same behavior)
```yaml
server:
  tools:
    - type: "read"
      name: "execute_query"
    - type: "write"
      name: "write_query"
    - type: "read"
      regexp: "^analytics\\..*_view$"
      prefix: "analytics_"
```

### After Issue #35 (Option 2: Minimal - rely on defaults)
```yaml
server:
  transport: stdio
  # No tools or dynamic_tools needed!
  # execute_query + write_query registered automatically
```

---

## Testing Backward Compatibility

### Test 1: No Config

```bash
# config.yaml
server:
  transport: stdio
```

**Expected logs:**
```
INFO  ClickHouse tools registered static_tool_count=2 dynamic_tool_rules=0
INFO  Static read tool registered tool=execute_query
INFO  Static write tool registered tool=write_query
```

### Test 2: Old Format

```bash
# config.yaml
server:
  dynamic_tools:
    - regexp: "^test\\..*_view$"
      prefix: "view_"
```

**Expected logs:**
```
WARN  dynamic_tools config is deprecated, use tools instead
INFO  ClickHouse tools registered static_tool_count=2 dynamic_tool_rules=1
INFO  Static read tool registered tool=execute_query
INFO  Static write tool registered tool=write_query
```

### Test 3: Read-Only Mode

```bash
# config.yaml
clickhouse:
  read_only: true
server:
  transport: stdio
```

**Expected logs:**
```
INFO  ClickHouse tools registered static_tool_count=1 dynamic_tool_rules=0
INFO  Static read tool registered tool=execute_query
INFO  Write tool skipped (read-only mode) tool=write_query
```

**MCP tools/list response:**
```json
{
  "tools": [
    {
      "name": "execute_query",
      "annotations": {
        "readOnlyHint": true,
        "destructiveHint": false
      }
    }
  ]
}
```

---

## Conclusion

✅ **Backward compatibility is fully maintained**:
- No `server.tools` config → defaults register automatically
- Old `server.dynamic_tools` → works with deprecation warning
- Tools are always announced with complete metadata
- Safety annotations inform clients about destructive capabilities
- Read-only mode properly restricts tool availability
