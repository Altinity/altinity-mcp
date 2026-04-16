# Issue #35 - Revised Implementation Plan

**Updated Based on User Feedback**

---

## Revised Approach

### Your Key Decisions

1. **Keep `execute_query` forever** (as safe, read-only tool)
   - Don't deprecate - just keep it as-is
   - Better than removing and breaking existing integrations

2. **No drop/truncate tools**
   - Rely on RBAC for access control
   - Makes sense: ClickHouse RBAC is mature and purpose-built
   - Avoid tool proliferation

3. **Create dynamic write tools from tables**
   - Similar to dynamic read tools (currently from views)
   - Exclude alias and materialized columns
   - Need better config structure

4. **Keep tool definitions lean**
   - Only create what's needed
   - Avoid context bloat

---

## Simplified Tool Strategy

### Hierarchy

```
Static Tools (always):
├── execute_query          → Read-safe (SELECT, SHOW, DESC, EXPLAIN, etc.)
├── write_query (NEW)      → Write operations (INSERT, UPDATE, DELETE, ALTER)
└── [For backwards compat, no deprecation needed]

Dynamic Read Tools (from Views):
├── rules-based discovery from system.tables WHERE engine='View'
├── metadata from view COMMENT
└── Example: analytics_db.user_stats_view → user_stats tool

Dynamic Write Tools (NEW, from Tables):
├── rules-based discovery from system.tables WHERE type='Table'
├── exclude: Alias, Materialized, MergeTree system tables
├── metadata from table COMMENT
└── Example: events_db.events_table → events_write tool
```

### Why This Works

- **No explosion of tools** - Only create what's explicitly configured
- **RBAC handles security** - No need for admin tools
- **Clear semantics** - execute_query (safe), write_query (risky), dynamic tools (explicit config)
- **Backwards compatible** - execute_query stays unchanged

---

## Part 1: Understanding Current Dynamic Tools

### Current Implementation (Read-Only from Views)

**Configuration:**
```yaml
server:
  dynamic_tools:
    - regexp: "mydb\\..*"
      prefix: "db_"
    - name: "get_user_data"
      regexp: "users\\.user_info_view"
```

**Discovery:**
```go
// Query: SELECT database, name, create_table_query, comment FROM system.tables WHERE engine='View'
// For each matching view, create a tool:
// - name: snakeCase(prefix + name or full_name)
// - title: humanizeToolName(name)
// - description: from COMMENT or auto-generated
// - params: parsed from CREATE VIEW query {param_name: Type}
// - annotations: from COMMENT JSON {"annotations": {"openWorldHint": true}}
```

**Tool Registration:**
```go
func EnsureDynamicTools(ctx context.Context) error {
    // 1. Fetch views from system.tables
    // 2. Match against regex rules
    // 3. For each match:
    //    - Parse parameters from CREATE VIEW
    //    - Parse comment for metadata
    //    - Create tool definition
    //    - Register with AddTool(tool, handler)
}
```

**Handler:**
```go
func makeDynamicToolHandler(meta dynamicToolMeta) {
    // 1. Get args from request
    // 2. Build param list: param_name=sqlLiteral(value)
    // 3. Build query: SELECT * FROM db.table(args...)
    // 4. Execute and return JSON
}
```

**Annotation Format in Comment:**
```json
{
  "title": "Custom Tool Title",
  "description": "Custom tool description",
  "annotations": {
    "openWorldHint": true
  }
}
```

All dynamic read tools automatically get:
```go
ReadOnlyHint:    true
DestructiveHint: false
OpenWorldHint:   (from comment, default false)
```

---

## Part 2: Proposed Dynamic Write Tools

### Key Requirements

1. **Source**: ClickHouse tables (not views)
2. **Exclude**:
   - Alias tables (engine = 'Alias')
   - Materialized view tables
   - System tables (system.*)
   - Temporary tables

3. **Columns**: Include regular columns only
   - Exclude: Alias columns, Materialized columns, virtual columns
   - Include: normal columns with all data types

4. **Parameters**: Support two modes
   - **Insert Mode**: Required columns only (for INSERT)
   - **Update Mode**: All non-key columns (for UPDATE)

5. **Metadata**: Same comment format as views
   ```json
   {
     "title": "Insert User Data",
     "description": "Insert new user records",
     "annotations": {
       "mode": "insert",  // or "update", or "upsert"
       "openWorldHint": false
     }
   }
   ```

### Configuration Structure

Current (read-only):
```yaml
dynamic_tools:
  - regexp: "mydb\\..*"
    prefix: "db_"
```

Proposed (extended):
```yaml
dynamic_tools:
  # Read tools from views (existing)
  - type: "read"           # optional, default
    regexp: "mydb\\..*"
    prefix: "db_read_"
  
  # Write tools from tables (new)
  - type: "write"
    regexp: "mydb\\..*"
    prefix: "db_write_"
    mode: "insert"         # insert, update, or upsert
```

### Implementation Structure

**New DynamicToolRule with type:**
```go
type DynamicToolRule struct {
    Type   string `json:"type" yaml:"type"`      // "read" or "write"
    Name   string `json:"name" yaml:"name"`
    Regexp string `json:"regexp" yaml:"regexp"`
    Prefix string `json:"prefix" yaml:"prefix"`
    Mode   string `json:"mode" yaml:"mode"`      // for write: "insert", "update", "upsert"
}
```

**Enhanced dynamicToolMeta:**
```go
type dynamicToolMeta struct {
    ToolName    string
    Title       string
    Database    string
    Table       string
    Description string
    Annotations *mcp.ToolAnnotations
    Params      []dynamicToolParam
    ToolType    string    // "read" or "write"
    WriteMode   string    // "insert", "update", "upsert"
}
```

---

## Part 3: Code Design for Dynamic Write Tools

### Step 1: Separate Discovery Functions

**Current monolithic approach:**
```go
func EnsureDynamicTools(ctx context.Context) error {
    // Discover views
    // Discover tables  ← needs separation
    // Register both types
}
```

**Proposed modular approach:**
```go
func EnsureDynamicTools(ctx context.Context) error {
    readTools := s.discoverReadTools(ctx)      // from views
    writeTools := s.discoverWriteTools(ctx)    // from tables
    s.registerDynamicTools(readTools, writeTools)
}

func (s *ClickHouseJWEServer) discoverReadTools(ctx context.Context) map[string]dynamicToolMeta {
    // Current logic: fetch views, match rules, build metadata
}

func (s *ClickHouseJWEServer) discoverWriteTools(ctx context.Context) map[string]dynamicToolMeta {
    // NEW: fetch tables, match write rules, extract columns, build metadata
}
```

### Step 2: Table Column Discovery

**Query to get column info:**
```sql
SELECT 
    database,
    table,
    name,
    type,
    column_type,     -- 'normal' | 'alias' | 'materialized' | 'virtual'
    default_kind     -- 'DEFAULT' | 'MATERIALIZED' | 'ALIAS' | 'EPHEMERAL'
FROM system.columns
WHERE database NOT IN ('system', 'INFORMATION_SCHEMA')
  AND table NOT IN ('system', 'numbers', 'numbers_mt')
  -- Filter out table types
  AND (database, table) IN (
    SELECT database, name 
    FROM system.tables 
    WHERE engine NOT IN ('Alias', 'View', 'MaterializedView')
  )
ORDER BY database, table, position
```

**Parsing columns:**
```go
type TableColumn struct {
    Name       string  // column name
    Type       string  // String, UInt32, etc.
    ColumnType string  // 'normal', 'alias', 'materialized', 'virtual'
    DefaultKind string // 'DEFAULT', 'MATERIALIZED', 'ALIAS'
}

func (s *ClickHouseJWEServer) getTableColumns(ctx context.Context, db, table string) ([]TableColumn, error) {
    // Fetch from system.columns
    // Filter: ColumnType == 'normal' && DefaultKind != 'MATERIALIZED'|'ALIAS'
    // Return non-virtual columns
}

func (s *ClickHouseJWEServer) getTableColumnsForMode(ctx context.Context, db, table string, mode string) ([]dynamicToolParam, error) {
    cols := s.getTableColumns(ctx, db, table)
    
    switch mode {
    case "insert":
        // Include all non-default columns
        return filterInsertableColumns(cols), nil
    
    case "update":
        // Include all columns (user can update anything)
        return cols, nil
    
    case "upsert":
        // Include all columns (INSERT + UPDATE)
        return cols, nil
    
    default:
        return nil, fmt.Errorf("unknown write mode: %s", mode)
    }
}

func filterInsertableColumns(cols []TableColumn) []dynamicToolParam {
    params := make([]dynamicToolParam, 0)
    
    for _, col := range cols {
        // Skip columns with MATERIALIZED default (auto-computed)
        if col.DefaultKind == "MATERIALIZED" || col.DefaultKind == "ALIAS" {
            continue
        }
        
        // Skip virtual columns
        if col.ColumnType == "virtual" {
            continue
        }
        
        params = append(params, dynamicToolParam{
            Name:       col.Name,
            CHType:     col.Type,
            JSONType:   chTypeToJSONType(col.Type),
            Required:   col.DefaultKind == "",  // Required if no default
        })
    }
    
    return params
}
```

### Step 3: Write Tool Handler

**Handler for dynamic write tools:**
```go
func makeDynamicWriteToolHandler(meta dynamicToolMeta) ToolHandlerFunc {
    return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        chJweServer := GetClickHouseJWEServerFromContext(ctx)
        if chJweServer == nil {
            return nil, fmt.Errorf("can't get JWEServer from context")
        }
        
        // Check not in read-only mode
        if chJweServer.Config.ClickHouse.ReadOnly {
            return NewToolResultError("write operations disabled in read-only mode"), nil
        }
        
        chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
        if err != nil {
            log.Error().Err(err).Str("tool", meta.ToolName).Msg("Failed to get ClickHouse client")
            return NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
        }
        defer chClient.Close()
        
        arguments := getArgumentsMap(req)
        
        // Build query based on mode
        query, err := buildDynamicWriteQuery(meta, arguments)
        if err != nil {
            return NewToolResultError(fmt.Sprintf("Invalid arguments: %v", err)), nil
        }
        
        // Execute
        result, err := chClient.ExecuteQuery(ctx, query)
        if err != nil {
            log.Error().Err(err).Str("tool", meta.ToolName).Str("query", query).Msg("Write query failed")
            return NewToolResultError(fmt.Sprintf("Query failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
        }
        
        // For INSERT, return "success" message instead of results
        return NewToolResultText(fmt.Sprintf("Successfully executed %s. Rows affected: %d", meta.ToolName, getAffectedRows(result))), nil
    }
}

func buildDynamicWriteQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error) {
    switch meta.WriteMode {
    case "insert":
        return buildInsertQuery(meta, args)
    case "update":
        return buildUpdateQuery(meta, args)
    case "upsert":
        return buildUpsertQuery(meta, args)
    default:
        return "", fmt.Errorf("unknown mode: %s", meta.WriteMode)
    }
}

func buildInsertQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error) {
    // Example output: INSERT INTO db.table (col1, col2) VALUES ('val1', val2)
    cols := make([]string, 0)
    vals := make([]string, 0)
    
    for _, param := range meta.Params {
        if val, ok := args[param.Name]; ok {
            cols = append(cols, param.Name)
            vals = append(vals, sqlLiteral(param.JSONType, val))
        } else if param.Required {
            return "", fmt.Errorf("required parameter missing: %s", param.Name)
        }
    }
    
    if len(cols) == 0 {
        return "", fmt.Errorf("no columns provided")
    }
    
    colList := strings.Join(cols, ", ")
    valList := strings.Join(vals, ", ")
    return fmt.Sprintf("INSERT INTO %s.%s (%s) VALUES (%s)", 
        meta.Database, meta.Table, colList, valList), nil
}

func buildUpdateQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error) {
    // UPDATE db.table SET col1 = 'val1', col2 = val2 WHERE condition
    // Requires WHERE clause in extra args?
    // This is tricky - maybe require WHERE_CLAUSE parameter
    
    // For now: simplified approach without WHERE clause
    // Return error: "UPDATE requires WHERE clause (not yet supported)"
    return "", fmt.Errorf("UPDATE not yet supported in dynamic tools; use write_query instead")
}
```

### Step 4: Discovery and Registration

```go
func (s *ClickHouseJWEServer) discoverWriteTools(ctx context.Context) map[string]dynamicToolMeta {
    // Get write rules from config
    writeRules := filterRulesByType(s.Config.Server.DynamicTools, "write")
    if len(writeRules) == 0 {
        return nil
    }
    
    chClient, err := s.getDiscoveryClient(ctx)
    if err != nil {
        log.Error().Err(err).Msg("dynamic_tools: failed to get client for write tool discovery")
        return nil
    }
    defer chClient.Close()
    
    // Query: SELECT database, name, comment FROM system.tables WHERE engine NOT IN (...)
    tables, err := s.fetchTableList(ctx, chClient)
    if err != nil {
        log.Error().Err(err).Msg("dynamic_tools: failed to list tables")
        return nil
    }
    
    tools := make(map[string]dynamicToolMeta)
    
    // Compile regex rules
    compiledRules := compileRules(writeRules)
    
    for _, table := range tables {
        // Match against rules
        matched := findMatchingRule(compiledRules, table.Database, table.Name)
        if matched == nil {
            continue
        }
        
        // Get columns for this mode
        cols, err := s.getTableColumnsForMode(ctx, chClient, table.Database, table.Name, matched.Mode)
        if err != nil {
            log.Warn().Str("table", table.Database+"."+table.Name).Err(err).Msg("failed to get columns")
            continue
        }
        
        // Build tool name
        toolName := snakeCase(matched.Prefix + table.Name)
        
        // Build metadata
        title, description, annotations := buildWriteToolPresentation(toolName, table.Database, table.Name, table.Comment, matched.Mode)
        
        tools[toolName] = dynamicToolMeta{
            ToolName:    toolName,
            Title:       title,
            Database:    table.Database,
            Table:       table.Name,
            Description: description,
            Annotations: annotations,
            Params:      cols,
            ToolType:    "write",
            WriteMode:   matched.Mode,
        }
    }
    
    log.Info().Int("write_tool_count", len(tools)).Msg("Dynamic write tools discovered")
    return tools
}

func buildWriteToolPresentation(toolName, db, table, comment, mode string) (string, string, *mcp.ToolAnnotations) {
    // Parse comment for metadata (same as read tools)
    metadata, hasStructured := parseDynamicToolComment(comment)
    
    // Generate title
    title := buildTitle(toolName, metadata.Title)
    
    // Generate description based on mode
    description := buildWriteToolDescription(comment, db, table, mode, metadata.Description, hasStructured)
    
    // Annotations: always destructive for write tools
    annotations := &mcp.ToolAnnotations{
        ReadOnlyHint:    false,
        DestructiveHint: boolPtr(true),
        OpenWorldHint:   boolPtr(false),
    }
    
    if metadata.Annotations != nil && metadata.Annotations.OpenWorldHint != nil {
        annotations.OpenWorldHint = boolPtr(*metadata.Annotations.OpenWorldHint)
    }
    
    return title, description, annotations
}

func buildWriteToolDescription(comment, db, table, mode, metadataDesc string, hasStructured bool) string {
    if strings.TrimSpace(metadataDesc) != "" {
        return strings.TrimSpace(metadataDesc)
    }
    
    modeDesc := ""
    switch mode {
    case "insert":
        modeDesc = "Insert new records"
    case "update":
        modeDesc = "Update existing records"
    case "upsert":
        modeDesc = "Insert or update records"
    }
    
    if hasStructured && strings.TrimSpace(comment) != "" {
        return fmt.Sprintf("%s into %s.%s. %s", modeDesc, db, table, comment)
    }
    
    if strings.TrimSpace(comment) != "" {
        return comment
    }
    
    return fmt.Sprintf("%s into %s.%s", modeDesc, db, table)
}
```

---

## Part 4: Configuration Examples

### Example 1: Simple Read + Write from Same Tables

```yaml
server:
  dynamic_tools:
    # Read operations from views
    - type: "read"
      regexp: "^analytics\\..*_view$"
      prefix: "analytics_"
    
    # Write operations from tables
    - type: "write"
      regexp: "^events\\..*_table$"
      prefix: "events_write_"
      mode: "insert"
```

### Example 2: Tiered Access (Read Views, Write Tables, Explicit Names)

```yaml
server:
  dynamic_tools:
    # Read: Named explicit tools
    - type: "read"
      name: "user_activity"
      regexp: "analytics\\.user_activity_view"
    
    - type: "read"
      name: "daily_stats"
      regexp: "analytics\\.daily_stats_view"
    
    # Write: Catch-all for specific database
    - type: "write"
      regexp: "^app_data\\..*"
      prefix: "insert_"
      mode: "insert"
```

### Example 3: Multi-Mode Write (Insert + Update)

```yaml
server:
  dynamic_tools:
    # Separate tools for different operations
    - type: "write"
      regexp: "^users\\..*"
      prefix: "create_"
      mode: "insert"
    
    - type: "write"
      regexp: "^users\\..*"
      prefix: "modify_"
      mode: "update"
```

---

## Part 5: File Structure and Code Organization

### Current Files
```
pkg/server/
├── server.go              (all static tools + dynamic tools)
├── oauth_*.go
└── ...
```

### Proposed Refactor (gradual)

**Keep in `server.go`:**
- Static tools: execute_query, read_query (NEW), write_query (NEW)
- Tool annotations and descriptions
- Main MCP server setup

**New file: `dynamic_tools.go`:**
```go
// Discovery
func (s *ClickHouseJWEServer) EnsureDynamicTools(ctx context.Context) error
func (s *ClickHouseJWEServer) discoverReadTools(ctx context.Context) map[string]dynamicToolMeta
func (s *ClickHouseJWEServer) discoverWriteTools(ctx context.Context) map[string]dynamicToolMeta
func (s *ClickHouseJWEServer) registerDynamicTools(readTools, writeTools map[string]dynamicToolMeta)

// Handlers
func makeDynamicToolHandler(meta dynamicToolMeta) ToolHandlerFunc
func makeDynamicWriteToolHandler(meta dynamicToolMeta) ToolHandlerFunc

// Metadata building
func buildDynamicToolMeta(toolName, db, table, comment string, params []dynamicToolParam, mode string) dynamicToolMeta
func buildWriteToolPresentation(toolName, db, table, comment, mode string) (string, string, *mcp.ToolAnnotations)

// Query building
func buildDynamicWriteQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error)
func buildInsertQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error)
func buildUpdateQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error)
```

**New file: `dynamic_tools_discovery.go`:**
```go
// Table discovery
func (s *ClickHouseJWEServer) fetchTableList(ctx context.Context, chClient *clickhouse.Client) ([]TableInfo, error)
func (s *ClickHouseJWEServer) getTableColumns(ctx context.Context, chClient *clickhouse.Client, db, table string) ([]TableColumn, error)
func (s *ClickHouseJWEServer) getTableColumnsForMode(ctx context.Context, chClient *clickhouse.Client, db, table, mode string) ([]dynamicToolParam, error)

// View discovery (existing logic extracted)
func (s *ClickHouseJWEServer) fetchViewList(ctx context.Context, chClient *clickhouse.Client) ([]ViewInfo, error)

// Utilities
func filterInsertableColumns(cols []TableColumn) []dynamicToolParam
func filterRulesByType(rules []DynamicToolRule, toolType string) []DynamicToolRule
func findMatchingRule(rules []compiledRule, db, table string) *compiledRule
```

---

## Part 6: Revised Tool Naming

### Current
```
execute_query      → read-safe, SELECT, SHOW, DESC, EXPLAIN
```

### New Static Tools
```
execute_query      → stays same (backwards compatible, read-safe)
write_query        → INSERT, UPDATE, DELETE, ALTER
```

### Why Not `read_query`?
- Less disruptive to existing integrations
- `execute_query` is actually accurate (executes queries)
- No deprecation needed

### Alternative Names for Write Operations

If you want a different name:
- `mutation_query` - Emphasizes data change
- `write_query` - Clear and standard
- `modify_query` - Explicit action
- `persist_query` - Data persistence focus
- `dml_query` - Technical term

**Recommendation**: Stick with `write_query` (matches industry standard - ClickHouse MCP, StarRocks MCP)

---

## Part 7: RBAC Strategy (No Admin Tools)

### Why No DROP/TRUNCATE Tools?

1. **ClickHouse RBAC is Purpose-Built**
   - Fine-grained control: database, table, column level
   - Prevents accidental drops at DB level
   - No need for tool-level enforcement

2. **Separation of Concerns**
   - Access control: Database RBAC
   - Data modification: Tool interface
   - Admin operations: Direct DB access or DBM tools

3. **Security Model**
   ```
   ✅ User wants to INSERT data:
      → Use write_query tool with INSERT statement
      → DB checks user RBAC for INSERT permission
      → Execute or deny
   
   ✅ User wants to DROP table:
      → Not available via MCP tool
      → User must have direct DB access
      → Admin explicitly grants DROP permission if needed
      → User uses DB CLI/API directly
   
   ❌ User tries to DROP via tool:
      → Tool doesn't exist
      → Clear boundary: "This tool can't do that"
   ```

4. **Configuration at DB Level**
   ```sql
   -- Grant INSERT/UPDATE/DELETE but NOT DROP
   GRANT INSERT, UPDATE, DELETE ON app_data.* TO user1
   
   -- Grant DROP only to admins with explicit need
   GRANT DROP ON app_data.* TO admin_user
   ```

---

## Part 8: Implementation Checklist

### Phase 1: Reorganize Config & Types
- [ ] Update `DynamicToolRule` to include `Type` and `Mode` fields
- [ ] Update `dynamicToolMeta` to include `ToolType` and `WriteMode`
- [ ] Update `dynamicToolCommentAnnotations` to support mode hints

### Phase 2: Extract Discovery Logic
- [ ] Create `dynamic_tools.go` for main discovery functions
- [ ] Create `dynamic_tools_discovery.go` for table/view/column queries
- [ ] Extract read tool discovery to `discoverReadTools()`
- [ ] Implement `discoverWriteTools()`

### Phase 3: Implement Write Tool Discovery
- [ ] Query system.columns for table structure
- [ ] Filter columns: exclude alias, materialized, virtual
- [ ] Handle different write modes (insert, update)
- [ ] Build tool metadata with correct annotations

### Phase 4: Implement Write Tool Handlers
- [ ] `makeDynamicWriteToolHandler()` factory
- [ ] `buildDynamicWriteQuery()` for query assembly
- [ ] `buildInsertQuery()` for INSERT statements
- [ ] Error handling for missing required parameters

### Phase 5: Static Tools (Minimal Changes)
- [ ] Rename `execute_query` → `read_query` internally, keep name as `execute_query`
- [ ] Add `write_query` static tool
- [ ] Ensure proper annotations

### Phase 6: Testing
- [ ] Unit tests for column filtering
- [ ] Unit tests for query building
- [ ] Integration tests with real ClickHouse
- [ ] Test read-only mode (write_query unavailable)
- [ ] Test dynamic tool discovery

### Phase 7: Documentation
- [ ] Update README with new configuration examples
- [ ] Document dynamic write tools in docs/dynamic_tools.md
- [ ] Add comment metadata examples for write tools
- [ ] RBAC configuration guide

---

## Part 9: YAML Configuration Reference

```yaml
# MINIMAL: Just read from views
server:
  dynamic_tools:
    - regexp: "mydb\\..*_view"
      prefix: "get_"

# FULL: Read + Write with modes
server:
  dynamic_tools:
    # Read operations
    - type: "read"
      name: "daily_report"
      regexp: "analytics\\.daily_report_view"
    
    - type: "read"
      regexp: "analytics\\..*_view"
      prefix: "analytics_"
    
    # Write: Insert
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"
    
    # Write: Update (separate)
    - type: "write"
      regexp: "users\\..*_table"
      prefix: "update_"
      mode: "update"
```

---

## Summary Table

| Aspect | Current | Proposed | Benefit |
|--------|---------|----------|---------|
| **Static Tools** | execute_query | execute_query, write_query | Clear safety semantics |
| **Dynamic Read** | Views only | Views + metadata | No change |
| **Dynamic Write** | None | Tables + metadata | New capability |
| **Admin Tools** | None | None (RBAC only) | Lean, secure design |
| **Config Structure** | Simple rule | Type + mode | Better semantics |
| **Deprecation** | No | No needed | Stability |
| **Tool Count** | ~2-50 | ~2-100 (but lean) | More options, intentional |

---

## Next Steps

1. **Clarification** (this document):
   - ✅ Keep execute_query forever (no deprecation)
   - ✅ New write_query for static writes
   - ✅ No DROP/TRUNCATE tools (RBAC instead)
   - ✅ Create dynamic write tools from tables
   - ✅ Exclude alias/materialized columns

2. **Review** (with your team):
   - Config changes look good?
   - write_query naming acceptable?
   - Implementation approach sound?
   - Any other tool types needed?

3. **Implementation** (if approved):
   - Start with discovery logic
   - Implement write tool handlers
   - Add tests
   - Update documentation

---

**Status**: Ready for discussion and feedback  
**Complexity**: Medium (code organization + new discovery)  
**Estimated Effort**: 2-3 weeks (careful implementation)  
**Risk**: Low (read-only discovery unchanged, write tools additive)
