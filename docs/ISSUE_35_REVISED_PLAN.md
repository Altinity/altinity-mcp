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

**Old Approach** (separate flags + dynamic_tools):
```yaml
server:
  tools:
    expose_static_write_query: false  # Flag-based control
  
  dynamic_tools:
    - type: "read"
      regexp: "mydb\\..*"
      prefix: "db_read_"
```

**New Unified Approach** (single tools array):
```yaml
server:
  tools:
    # Static tools (explicit)
    - type: "read"
      name: "execute_query"    # No regexp = static tool
    
    - type: "write"
      name: "write_query"      # No regexp = static tool
    
    # Dynamic read tools from views
    - type: "read"
      regexp: "mydb\\..*"      # Has regexp = dynamic tool
      prefix: "db_read_"
    
    # Dynamic write tools from tables
    - type: "write"
      regexp: "mydb\\..*"      # Has regexp = dynamic tool
      prefix: "db_write_"
      mode: "insert"
```

**Why Unified Config?**
- ✅ Single source of truth (all tools in one place)
- ✅ Config-as-code for everything (no hardcoded tools)
- ✅ Clear visual hierarchy (static vs dynamic)
- ✅ Easy to hide/show tools (just don't list them)
- ✅ Extensible (add more static tools easily)
- ✅ No special flags needed

### Implementation Structure

**Unified ToolDefinition (supports both static and dynamic):**
```go
type ToolDefinition struct {
    Type      string `json:"type" yaml:"type"`        // "read" or "write"
    Name      string `json:"name" yaml:"name"`        // Static tool name (optional, if no regexp)
    Regexp    string `json:"regexp" yaml:"regexp"`    // Dynamic discovery pattern (optional)
    Prefix    string `json:"prefix" yaml:"prefix"`    // Tool prefix for discovered tools
    Mode      string `json:"mode" yaml:"mode"`        // For write: "insert", "update", "upsert"
}

// In config parsing, tools can be:
// - Static (has Name, no Regexp): execute_query, write_query, custom tools
// - Dynamic (has Regexp, no Name): discovered from views/tables
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
    IsStatic    bool      // true if static, false if dynamic
}
```

**Processing Logic (Unified):**
```go
func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    if len(cfg.Server.Tools) == 0 {
        // Use defaults: execute_query + write_query
        registerDefaultTools(srv)
        return
    }
    
    for _, toolDef := range cfg.Server.Tools {
        if toolDef.Name != "" && toolDef.Regexp == "" {
            // Static tool (has name, no regexp)
            registerStaticTool(srv, toolDef)
        } else if toolDef.Regexp != "" {
            // Dynamic tool (has regexp, will discover)
            addDynamicToolRule(cfg, toolDef)
        } else {
            log.Error().Msg("Tool definition must have either name (static) or regexp (dynamic)")
        }
    }
    
    // Discover and register dynamic tools
    srv.EnsureDynamicTools(ctx)
}

func registerStaticTool(srv AltinityMCPServer, def ToolDefinition) {
    switch def.Type {
    case "read":
        if def.Name == "execute_query" {
            srv.AddTool(executeQueryTool, HandleExecuteQuery)
        } else {
            // Custom read tool
            log.Warn().Str("name", def.Name).Msg("Unknown static read tool")
        }
    case "write":
        if def.Name == "write_query" {
            srv.AddTool(writeQueryTool, HandleWriteQuery)
        } else {
            // Custom write tool
            log.Warn().Str("name", def.Name).Msg("Unknown static write tool")
        }
    }
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

### Example 1: Minimal (Just Static Tools, Default Behavior)

```yaml
server:
  tools: []
  # Empty: uses code defaults (execute_query + write_query)
```

Or explicit:
```yaml
server:
  tools:
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
```

### Example 2: Simple Read + Write from Tables

```yaml
server:
  tools:
    # Static tools (always available)
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    # Dynamic read operations from views
    - type: "read"
      regexp: "^analytics\\..*_view$"
      prefix: "analytics_"
    
    # Dynamic write operations from tables
    - type: "write"
      regexp: "^events\\..*_table$"
      prefix: "events_write_"
      mode: "insert"
```

### Example 3: Hide Generic Tool, Use Only Dynamic (Schema-Validated)

```yaml
server:
  tools:
    # Only read-safe tool
    - type: "read"
      name: "execute_query"
    
    # NO generic write_query - only specific dynamic tools
    
    # Dynamic write tools from tables (schema-validated)
    - type: "write"
      regexp: "^events\\..*_table$"
      prefix: "log_"
      mode: "insert"
    
    - type: "write"
      regexp: "^users\\..*_table$"
      prefix: "create_"
      mode: "insert"
```

### Example 4: Tiered Access (Read Views, Multi-Mode Writes)

```yaml
server:
  tools:
    # Static tools
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    # Dynamic read: analytics views
    - type: "read"
      regexp: "^analytics\\..*_view$"
      prefix: "get_"
    
    # Dynamic write: insert into event tables
    - type: "write"
      regexp: "^events\\..*_table$"
      prefix: "log_"
      mode: "insert"
    
    # Dynamic write: update user tables
    - type: "write"
      regexp: "^users\\..*_table$"
      prefix: "update_"
      mode: "update"
```

### Example 5: Multi-Mode Write (Insert + Update from Same Tables)

```yaml
server:
  tools:
    # Static tools
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    # Dynamic: separate tools for INSERT vs UPDATE on same tables
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

### Phase 1: Update Config Structure (Unified Tools) ✅
- [x] Create `ToolDefinition` struct (supports static + dynamic)
  - [x] `Type` (read|write)
  - [x] `Name` (static tool name, optional)
  - [x] `Regexp` (dynamic discovery, optional)
  - [x] `Prefix` (for dynamic naming)
  - [x] `Mode` (for write: insert|update|upsert)
- [x] Update `ServerConfig` to use `Tools []ToolDefinition` in addition to DynamicTools
- [x] Keep backwards compat: old `DynamicTools` still supported with migration warning
- [x] Update config conversion logic for unmarshaling

### Phase 2: Refactor RegisterTools() Function ✅
- [x] Update `RegisterTools()` to iterate `Tools` array
- [x] Add logic to detect static vs dynamic (Name vs Regexp)
- [x] Implement `registerStaticTool()` for execute_query, write_query
- [x] Implement conversion from old DynamicTools format
- [x] Add default tool registration if config empty (execute_query + write_query)

### Phase 3: Extract Dynamic Tool Discovery ✅
- [x] Refactor `EnsureDynamicTools()` to call separate functions
- [x] Extract `discoverReadTools()` from views
- [x] Implement `discoverWriteTools()` from tables
- [x] Add `registerDynamicTools()` for unified registration
- [x] Add helper `filterRulesByType()` to separate read/write rules
- [x] Update `dynamicToolMeta` struct with `ToolType` and `WriteMode`

### Phase 4: Implement Write Tool Capability ✅
- [x] Implement `discoverWriteTools()` with table discovery
- [x] Query `system.columns` for table structure
- [x] Implement `getTableColumnsForMode()` column filtering
  - [x] Exclude alias columns (ColumnType='alias')
  - [x] Exclude materialized columns (ColumnType='materialized')
  - [x] Exclude virtual columns (ColumnType='virtual')
  - [x] Exclude auto-default columns (DefaultKind='MATERIALIZED'|'ALIAS')
- [x] Handle insert mode (required columns)
- [x] Build tool metadata with destructive annotations
- [x] Add write tool description builder

### Phase 5: Implement Write Tool Handlers ✅
- [x] `makeDynamicWriteToolHandler()` factory function
- [x] `buildDynamicWriteQuery()` dispatcher
- [x] `buildInsertQuery()` for INSERT statements with parameter validation
- [x] Stub for `buildUpdateQuery()` with deferred implementation note
- [x] Error handling for missing/invalid parameters
- [x] Read-only mode check in write handler

### Phase 6: Testing (Deferred)
- [ ] Unit tests for ToolDefinition parsing
- [ ] Unit tests for column filtering logic
- [ ] Unit tests for query building (insert)
- [ ] Integration tests with real ClickHouse
- [ ] Test read-only mode (write tools unavailable)
- [ ] Test dynamic discovery with regex matching
- [ ] Test backwards compat (old config still works)

### Phase 7: Documentation (In Progress)
- [ ] Update README with unified tools config examples
- [ ] Document tool definition structure (static vs dynamic)
- [ ] Add examples: hide generic tool, use dynamic only
- [ ] Add examples: multi-mode writes (insert + update)
- [ ] Document column filtering rules
- [ ] RBAC configuration guide
- [ ] Migration guide from old config

---

## Part 9: YAML Configuration Reference

```yaml
# MINIMAL: Default static tools only
server:
  tools: []
  # Results in: execute_query, write_query (always enabled)

# FULL: Explicit static + dynamic tools
server:
  tools:
    # === STATIC TOOLS ===
    - type: "read"
      name: "execute_query"       # No regexp = static
    
    - type: "write"
      name: "write_query"         # No regexp = static
    
    # === DYNAMIC READ TOOLS ===
    - type: "read"
      name: "daily_report"        # Optional explicit name
      regexp: "analytics\\.daily_report_view"
    
    - type: "read"
      regexp: "analytics\\..*_view"  # Has regexp = dynamic
      prefix: "analytics_"
    
    # === DYNAMIC WRITE TOOLS ===
    # Write: Insert mode
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"              # insert, update, or upsert
    
    # Write: Update mode (separate)
    - type: "write"
      regexp: "users\\..*_table"
      prefix: "update_"
      mode: "update"

# MINIMAL WITH DYNAMICS: Static + selective dynamic
server:
  tools:
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    - type: "write"
      regexp: "^events\\..*"
      prefix: "log_"
      mode: "insert"
```

---

## Summary Table

| Aspect | Current | Unified Config | Benefit |
|--------|---------|-----------------|---------|
| **Static Tools** | execute_query (hard-coded) | In `tools` array with `name` field | Config-as-code, explicit |
| **Dynamic Tools** | Separate `dynamic_tools` | In `tools` array with `regexp` field | Single source of truth |
| **Tool Visibility** | Flag-based (`expose_*`) | Just omit from config | Simpler, no flags |
| **Dynamic Read** | Views (type optional) | Type "read" + regexp | Clear semantics |
| **Dynamic Write** | None | Type "write" + regexp + mode | New capability |
| **Admin Tools** | None | None (RBAC only) | Lean, secure design |
| **Config Sections** | 2 (`tools`, `dynamic_tools`) | 1 (`tools`) | Unified, cleaner |
| **Backwards Compat** | N/A | Supports old format | Smooth migration |
| **Tool Count** | ~2-50 | ~2-100 (lean, intentional) | Explicit control |

---

## Implementation Status

### Completed ✅

**Phases 1-5 Implementation**:
- [x] Config structure updated: New `ToolDefinition` struct, `ServerConfig.Tools` array
- [x] `RegisterTools()` refactored to handle unified config with backwards compat
- [x] Dynamic tool discovery separated: `discoverReadTools()`, `discoverWriteTools()`, `registerDynamicTools()`
- [x] Write tool capability implemented:
  - [x] Table discovery from `system.tables`
  - [x] Column filtering (exclude alias, materialized, virtual, auto-default)
  - [x] Mode support (insert, update stubs, upsert stub)
  - [x] Metadata building with destructive annotations
- [x] Write tool handlers:
  - [x] `makeDynamicWriteToolHandler()` with read-only check
  - [x] `buildDynamicWriteQuery()` dispatcher
  - [x] `buildInsertQuery()` with parameter validation
  - [x] `buildUpdateQuery()` and `buildUpsertQuery()` stubs

**Code Status**:
- ✅ Compiles successfully
- ✅ Backwards compatible (old `DynamicTools` config still works)
- ✅ Unified `tools` array now primary config method
- ✅ READ_ONLY mode prevents write tool registration

### Deferred (Phase 6-7)

**Testing & Documentation**:
- Unit tests for column filtering, query building
- Integration tests with real ClickHouse
- Documentation updates (examples, migration guide, RBAC guide)
- Configuration examples in README

---

**Current Status**: Core implementation complete, code compiles  
**Code Files Modified**:
- `pkg/config/config.go`: New `ToolDefinition` struct, `ServerConfig.Tools` field
- `pkg/server/server.go`: Refactored `RegisterTools()`, new discovery functions, write tool handlers

**Backwards Compatibility**: ✅ Fully maintained
- Old `DynamicTools` config still works (with deprecation warning)
- Existing `execute_query` tool unchanged
- New `write_query` tool optional
- New dynamic write tools opt-in via config

**Unified Config Approach**: ✅ Implemented
- Single `tools` array containing static + dynamic definitions
- Static tools: `type + name` (no regexp)
- Dynamic tools: `type + regexp + prefix + mode`
- Can hide generic tools by omitting from config
