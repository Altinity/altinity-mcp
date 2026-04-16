# Issue #35: Tool Splitting Implementation Plan

**Status**: Ready for development  
**Complexity**: Medium  
**Estimated Effort**: 1-2 sprints  
**Breaking Change**: No (backwards compatible)

---

## Problem Statement (from Issue #35)

### Current Problem

The `execute_query` tool is marked as destructive even when executing harmless SELECT queries, causing:

1. **Anthropic Claude Code**: Unnecessary confirmation prompts for read operations
2. **OpenAI ChatGPT**: Same confirmation friction via x-openai-isConsequential flag
3. **User Experience**: "Show me the users table" triggers approval dialogs

### Root Cause

**Single tool, mixed responsibilities:**
- Accepts both `SELECT * FROM users` (harmless)
- Accepts `DELETE FROM users` (destructive)
- Marked with `DestructiveHint: true` globally
- No server-side validation distinguishing safe from unsafe statements

### Industry Solution

ClickHouse and StarRocks MCP servers solved this with **tool splitting**:
- `read_query` - SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS, WITH (safe)
- `write_query` - INSERT, UPDATE, DELETE, ALTER (risky)
- Optional `admin_query` - DROP, TRUNCATE (very risky, locked by default)

---

## Solution Design

### 1. New Tool Structure

```
read_query
├── Input: query (SELECT-like), limit (optional)
├── Annotations: ReadOnly=true, Destructive=false
├── Behavior: Allows SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS, WITH
├── Confirmation: None (safe)
└── Visibility: Always registered

write_query
├── Input: query (INSERT/UPDATE/DELETE/ALTER), limit (optional)
├── Annotations: ReadOnly=false, Destructive=true
├── Behavior: Allows INSERT, UPDATE, DELETE, ALTER TABLE
├── Confirmation: Always (risky)
├── Visibility: NOT registered if --read-only flag
└── Error: Rejects SELECT queries

execute_query [DEPRECATED]
├── Input: query (any), limit (optional)
├── Annotations: depends on --read-only mode
├── Behavior: Auto-routes to read_query or write_query
├── Confirmation: Depends on statement type
├── Visibility: Always registered (backwards compatibility)
└── Deprecation: Marked in description and logs
```

### 2. Statement Classification

**New function: `classifyStatement(query string) StatementType`**

```go
type StatementType int

const (
    StmtRead    StatementType = iota  // SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS, WITH
    StmtWrite                         // INSERT, UPDATE, DELETE, ALTER
    StmtAdmin                         // DROP, TRUNCATE
    StmtUnknown                       // Unrecognized
)

func classifyStatement(query string) StatementType {
    // Remove SQL comments
    // Trim and uppercase
    // Check first keyword against patterns
    // Return classification
}
```

**Classification Logic**:
```
Input: "SELECT * FROM users LIMIT 10"
→ Remove comments: "SELECT * FROM users LIMIT 10"
→ ToUpper: "SELECT * FROM USERS LIMIT 10"
→ Extract prefix: "SELECT"
→ Match pattern: "SELECT" in readPatterns
→ Return: StmtRead
```

### 3. Handler Behavior

**Three handler functions**:

```go
// Safe to call for SELECT queries
func HandleReadQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // 1. Validate statement is read-only
    // 2. Execute with read_query handler
    // 3. Return results
}

// Validates before write
func HandleWriteQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // 1. Check not in read-only mode (error if yes)
    // 2. Validate statement is write (not read, not admin)
    // 3. Execute with write_query handler
    // 4. Return results
}

// Auto-routes (backwards compatibility)
func HandleExecuteQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // 1. Classify statement
    // 2. Route to read_query or write_query handler
    // 3. If read: execute
    // 4. If write: check not read-only, then execute
    // 5. If admin: reject (or separate handler if enabled)
}
```

### 4. Registration Logic

```go
func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    // ALWAYS register
    srv.AddTool(newReadQueryTool(), HandleReadQuery)
    
    // Only if NOT read-only
    if !cfg.ClickHouse.ReadOnly {
        srv.AddTool(newWriteQueryTool(), HandleWriteQuery)
    }
    
    // Always register (backwards compatibility, deprecated)
    srv.AddTool(newDeprecatedExecuteQueryTool(cfg.ClickHouse.ReadOnly), HandleExecuteQuery)
    
    // Log registration summary
    logToolsRegistered(cfg.ClickHouse.ReadOnly)
}
```

---

## Implementation Details

### Phase 1: Core Validation & Classification

**Files to create/modify**:

1. **New function in `server.go`:**

```go
// StatementType represents SQL statement classification
type StatementType int

const (
    StmtRead    StatementType = iota
    StmtWrite
    StmtAdmin
    StmtUnknown
)

// classifyStatement analyzes SQL and returns statement type
func classifyStatement(query string) StatementType {
    // Remove both single-line and multi-line comments
    cleaned := removeComments(query)
    
    // Get first keyword
    trimmed := strings.TrimSpace(strings.ToUpper(cleaned))
    
    // Extract first word
    firstWord := extractFirstWord(trimmed)
    
    // Classify by first keyword
    switch firstWord {
    case "SELECT", "WITH", "SHOW", "DESC", "DESCRIBE", "EXPLAIN", "EXISTS":
        return StmtRead
    
    case "INSERT", "UPDATE", "DELETE", "ALTER":
        return StmtWrite
    
    case "DROP", "TRUNCATE":
        return StmtAdmin
    
    default:
        return StmtUnknown
    }
}

// isStatementAllowedInTool checks if statement is allowed in specific tool
func isStatementAllowedInTool(toolName string, stmt StatementType) error {
    switch toolName {
    case "read_query":
        if stmt != StmtRead {
            return fmt.Errorf("read_query only allows SELECT, WITH, SHOW, DESC, EXPLAIN, EXISTS. Got %v", stmt)
        }
    
    case "write_query":
        if stmt == StmtRead {
            return fmt.Errorf("write_query does not allow read operations. Use read_query instead")
        }
        if stmt == StmtAdmin {
            return fmt.Errorf("write_query does not allow admin operations (DROP, TRUNCATE)")
        }
        if stmt == StmtUnknown {
            return fmt.Errorf("write_query: unable to determine statement type")
        }
    
    case "execute_query":
        // Legacy: no restrictions here (validated elsewhere)
        // Restrictions enforced by caller based on config.ReadOnly
        if stmt == StmtUnknown {
            return fmt.Errorf("execute_query: unable to determine statement type")
        }
    
    default:
        return fmt.Errorf("unknown tool: %s", toolName)
    }
    
    return nil
}
```

### Phase 2: Tool Definition

```go
// newReadQueryTool creates the read_query tool
func newReadQueryTool() *mcp.Tool {
    return &mcp.Tool{
        Name:  "read_query",
        Title: "Execute Read-Only Query",
        Description: `Execute safe read-only SQL queries.

Supported statements: SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, EXISTS

The results are returned in JSON format, limited to the configured maximum number of rows.

Examples:
  - SELECT * FROM table_name
  - SHOW TABLES
  - DESCRIBE table_name
  - EXPLAIN SELECT * FROM table_name`,
        
        Annotations: &mcp.ToolAnnotations{
            ReadOnlyHint:    true,
            DestructiveHint: boolPtr(false),
            IdempotentHint:  boolPtr(true),
            OpenWorldHint:   boolPtr(false),
        },
        
        InputSchema: map[string]any{
            "type": "object",
            "properties": map[string]any{
                "query": map[string]any{
                    "type":        "string",
                    "description": "SQL read-only query. Only SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, EXISTS are allowed.",
                },
                "limit": map[string]any{
                    "type":        "number",
                    "description": "Maximum number of rows to return (default: server-configured limit, max: 10000)",
                },
            },
            "required": []string{"query"},
        },
    }
}

// newWriteQueryTool creates the write_query tool
func newWriteQueryTool() *mcp.Tool {
    return &mcp.Tool{
        Name:  "write_query",
        Title: "Execute Write Query",
        Description: `Execute SQL write operations (INSERT, UPDATE, DELETE, ALTER).

WARNING: These operations modify data and cannot be undone. Always review changes carefully.

Supported statements: INSERT, UPDATE, DELETE, ALTER TABLE

Examples:
  - INSERT INTO table_name (col1, col2) VALUES (val1, val2)
  - UPDATE table_name SET col1 = value WHERE condition
  - DELETE FROM table_name WHERE condition
  - ALTER TABLE table_name ADD COLUMN new_col String`,
        
        Annotations: &mcp.ToolAnnotations{
            ReadOnlyHint:    false,
            DestructiveHint: boolPtr(true),
            IdempotentHint:  boolPtr(false),
            OpenWorldHint:   boolPtr(false),
        },
        
        InputSchema: map[string]any{
            "type": "object",
            "properties": map[string]any{
                "query": map[string]any{
                    "type":        "string",
                    "description": "SQL write query. Only INSERT, UPDATE, DELETE, ALTER are allowed.",
                },
                "limit": map[string]any{
                    "type":        "number",
                    "description": "Optional row limit (for UPDATE/DELETE with LIMIT clause)",
                },
            },
            "required": []string{"query"},
        },
    }
}

// newDeprecatedExecuteQueryTool creates the legacy execute_query tool
func newDeprecatedExecuteQueryTool(readOnly bool) *mcp.Tool {
    return &mcp.Tool{
        Name:  "execute_query",
        Title: "[DEPRECATED] Execute Query",
        Description: `[DEPRECATED: Use read_query or write_query instead]

This tool auto-routes queries to read_query or write_query based on statement type.

For better safety and clearer intent:
  - Use read_query for SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS, WITH
  - Use write_query for INSERT, UPDATE, DELETE, ALTER

Supported statements: All SQL statements (subject to read-only mode)`,
        
        Annotations: makeExecuteQueryAnnotations(readOnly),
        
        InputSchema: map[string]any{
            "type": "object",
            "properties": map[string]any{
                "query": map[string]any{
                    "type":        "string",
                    "description": "SQL query to execute. In read-only mode, only SELECT/WITH/SHOW/DESC/EXISTS/EXPLAIN are allowed.",
                },
                "limit": map[string]any{
                    "type":        "number",
                    "description": "Maximum number of rows to return (default: 100000)",
                },
            },
            "required": []string{"query"},
        },
    }
}
```

### Phase 3: Handler Implementation

```go
// HandleReadQuery executes read-only queries
func HandleReadQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    arguments := getArgumentsMap(req)
    
    // Get query parameter
    queryArg, ok := arguments["query"]
    if !ok {
        return NewToolResultError("query parameter is required"), nil
    }
    
    query, ok := queryArg.(string)
    if !ok || query == "" {
        return NewToolResultError("query must be a non-empty string"), nil
    }
    
    // Validate statement type
    stmtType := classifyStatement(query)
    if err := isStatementAllowedInTool("read_query", stmtType); err != nil {
        return NewToolResultError(fmt.Sprintf("Invalid query for read_query: %v", err)), nil
    }
    
    // Get limit if provided
    var limit float64
    if limitVal, exists := arguments["limit"]; exists {
        if l, ok := limitVal.(float64); ok && l > 0 {
            limit = l
        }
    }
    
    // Execute query (reuse existing logic)
    return executeQueryInternal(ctx, query, limit, "read_query")
}

// HandleWriteQuery executes write operations
func HandleWriteQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // Get server from context
    chJweServer := GetClickHouseJWEServerFromContext(ctx)
    if chJweServer == nil {
        return nil, fmt.Errorf("can't get JWEServer from context")
    }
    
    // Check not in read-only mode
    if chJweServer.Config.ClickHouse.ReadOnly {
        return NewToolResultError("write_query is disabled in read-only mode"), nil
    }
    
    arguments := getArgumentsMap(req)
    
    // Get query parameter
    queryArg, ok := arguments["query"]
    if !ok {
        return NewToolResultError("query parameter is required"), nil
    }
    
    query, ok := queryArg.(string)
    if !ok || query == "" {
        return NewToolResultError("query must be a non-empty string"), nil
    }
    
    // Validate statement type
    stmtType := classifyStatement(query)
    if err := isStatementAllowedInTool("write_query", stmtType); err != nil {
        return NewToolResultError(fmt.Sprintf("Invalid query for write_query: %v", err)), nil
    }
    
    // Get limit if provided
    var limit float64
    if limitVal, exists := arguments["limit"]; exists {
        if l, ok := limitVal.(float64); ok && l > 0 {
            limit = l
        }
    }
    
    // Execute query (reuse existing logic)
    return executeQueryInternal(ctx, query, limit, "write_query")
}

// HandleExecuteQuery (legacy) routes to read_query or write_query
func HandleExecuteQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // Get server from context
    chJweServer := GetClickHouseJWEServerFromContext(ctx)
    if chJweServer == nil {
        return nil, fmt.Errorf("can't get JWEServer from context")
    }
    
    arguments := getArgumentsMap(req)
    
    // Get query parameter
    queryArg, ok := arguments["query"]
    if !ok {
        return NewToolResultError("query parameter is required"), nil
    }
    
    query, ok := queryArg.(string)
    if !ok || query == "" {
        return NewToolResultError("query must be a non-empty string"), nil
    }
    
    // Classify statement
    stmtType := classifyStatement(query)
    
    // Check read-only constraints
    if chJweServer.Config.ClickHouse.ReadOnly && stmtType != StmtRead {
        return NewToolResultError("read-only mode: only SELECT, WITH, SHOW, DESC, EXPLAIN, EXISTS allowed"), nil
    }
    
    // Log deprecation warning
    log.Warn().
        Str("query_prefix", query[:min(50, len(query))]+"...").
        Msg("execute_query is deprecated; use read_query or write_query instead")
    
    // Get limit if provided
    var limit float64
    if limitVal, exists := arguments["limit"]; exists {
        if l, ok := limitVal.(float64); ok && l > 0 {
            limit = l
        }
    }
    
    // Execute
    return executeQueryInternal(ctx, query, limit, "execute_query")
}

// executeQueryInternal contains shared query execution logic
func executeQueryInternal(ctx context.Context, query string, limit float64, toolName string) (*mcp.CallToolResult, error) {
    // Get server from context
    chJweServer := GetClickHouseJWEServerFromContext(ctx)
    if chJweServer == nil {
        return nil, fmt.Errorf("can't get JWEServer from context")
    }
    
    // Check limit against config
    if chJweServer.Config.ClickHouse.Limit > 0 && int(limit) > chJweServer.Config.ClickHouse.Limit {
        return NewToolResultError(fmt.Sprintf("limit cannot exceed %d", chJweServer.Config.ClickHouse.Limit)), nil
    }
    
    // Add LIMIT clause for SELECT if needed
    if isSelectQuery(query) && limit > 0 && !hasLimitClause(query) {
        query = fmt.Sprintf("%s LIMIT %.0f", strings.TrimSpace(query), limit)
    }
    
    // Get ClickHouse client
    chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
    if err != nil {
        log.Error().Err(err).Msg("Failed to get ClickHouse client")
        return NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
    }
    defer chClient.Close()
    
    // Execute query
    result, err := chClient.ExecuteQuery(ctx, query)
    if err != nil {
        log.Error().
            Err(err).
            Str("tool", toolName).
            Str("query_prefix", query[:min(100, len(query))]+"...").
            Msg("Query execution failed")
        return NewToolResultError(fmt.Sprintf("Query execution failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
    }
    
    // Marshal to JSON
    jsonData, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        return NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
    }
    
    return NewToolResultText(string(jsonData)), nil
}
```

### Phase 4: OpenAPI Endpoint Updates

```go
// In OpenAPI handler, add new routes
func (s *ClickHouseJWEServer) ServeOpenAPISchema(w http.ResponseWriter, r *http.Request) {
    schema := buildOpenAPISchema(s.Config)
    
    // Conditional: Include write_query endpoint only if not read-only
    if !s.Config.ClickHouse.ReadOnly {
        schema["paths"]["/{token}/openapi/write_query"] = buildWriteQueryEndpoint()
    }
    
    // Schema includes read_query, deprecated execute_query
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(schema)
}

func buildReadQueryEndpoint() map[string]any {
    return map[string]any{
        "get": map[string]any{
            "operationId": "read_query",
            "description": "Execute read-only SQL query",
            "x-openai-isConsequential": false,  // Safe for ChatGPT
            "parameters": []map[string]any{
                {
                    "name": "query",
                    "in": "query",
                    "required": true,
                    "schema": map[string]string{"type": "string"},
                },
                {
                    "name": "limit",
                    "in": "query",
                    "required": false,
                    "schema": map[string]string{"type": "integer"},
                },
            },
            "responses": map[string]any{
                "200": map[string]string{
                    "description": "Query results",
                    "content": map[string]any{
                        "application/json": map[string]any{
                            "schema": map[string]string{
                                "type": "object",
                            },
                        },
                    },
                },
            },
        },
    }
}

func buildWriteQueryEndpoint() map[string]any {
    return map[string]any{
        "post": map[string]any{
            "operationId": "write_query",
            "description": "Execute write SQL query (INSERT, UPDATE, DELETE, ALTER)",
            "x-openai-isConsequential": true,  // Always confirm in ChatGPT
            "requestBody": map[string]any{
                "required": true,
                "content": map[string]any{
                    "application/json": map[string]any{
                        "schema": map[string]any{
                            "type": "object",
                            "properties": map[string]any{
                                "query": map[string]string{
                                    "type": "string",
                                },
                                "limit": map[string]string{
                                    "type": "integer",
                                },
                            },
                            "required": []string{"query"},
                        },
                    },
                },
            },
            "responses": map[string]any{
                "200": map[string]string{
                    "description": "Operation results",
                },
            },
        },
    }
}
```

---

## Testing Strategy

### Unit Tests

```go
TestClassifyStatement:
  - classify("SELECT * FROM users") → StmtRead
  - classify("INSERT INTO users VALUES (...)") → StmtWrite
  - classify("DROP TABLE users") → StmtAdmin
  - classify("-- comment\nSELECT * FROM users") → StmtRead (handles comments)
  - classify("/* multi\n   line */SELECT") → StmtRead
  - classify("WITH cte AS (...) SELECT ...") → StmtRead
  - classify("unrecognized statement") → StmtUnknown

TestIsStatementAllowedInTool:
  - read_query + SELECT → allowed
  - read_query + INSERT → error
  - write_query + INSERT → allowed
  - write_query + SELECT → error (should use read_query)
  - write_query + DROP → error (admin operation)

TestToolRegistration:
  - Normal mode: read_query, write_query, execute_query registered
  - Read-only mode: read_query, execute_query registered; write_query not
  - Verify annotations on each tool
```

### Integration Tests

```go
TestReadQueryHandler:
  - Execute SELECT → returns results
  - Execute SHOW → returns results
  - Attempt INSERT → returns error
  - Attempt DELETE → returns error

TestWriteQueryHandler:
  - Normal mode: Execute INSERT → success
  - Normal mode: Execute UPDATE → success
  - Normal mode: Execute DELETE → success
  - Normal mode: Execute SELECT → error (wrong tool)
  - Read-only mode: Any attempt → error (tool unavailable or error)

TestExecuteQueryHandler (legacy):
  - Execute SELECT → returns results
  - Execute INSERT → returns results (mixed bag - for compatibility)
  - Execute DELETE → returns results
  - Verify deprecation warning logged
```

### Compatibility Tests

```go
TestBackwardsCompatibility:
  - Old client using execute_query still works
  - New client using read_query works
  - New client using write_query works
  - Both old and new clients can coexist

TestOpenAPIEndpoints:
  - /openapi/read_query available
  - /openapi/write_query available when not read-only
  - x-openai-isConsequential flags correct
  - Schema includes all three tools/endpoints
```

---

## Migration Path

### Version X.Y.Z (This Release)

```go
// ✅ New tools added
- read_query (NEW)
- write_query (NEW, conditional)
- execute_query (DEPRECATED - marked in description)

// ✅ Behavior
- Split validation and routing
- Deprecation warnings in logs
- Full OpenAPI support
- Read-only mode: write_query not registered

// ✅ Documentation
- README updated with new tools
- Migration guide for users
- Backwards compatibility guaranteed
```

### Version X.Y+1.Z (Next Minor)

```go
// ✅ Same functionality
- All three tools still available
- Continued support for execute_query
- No breaking changes

// ℹ️ Communication
- Blog post about migration
- Notification to integrations
- FAQ: "When will execute_query be removed?"
```

### Version X.Y+2.Z (Future Decision)

```go
// Options:
// A) Keep execute_query forever (for stability)
// B) Remove execute_query (long deprecation done)
// C) Keep in extended support (LTS version)

// Criteria for removal:
- No major integrations using execute_query
- 2+ minor versions released with deprecation warning
- User feedback: preference for split tools
```

---

## Configuration Changes

### CLI Flags (no changes needed)

```bash
# Existing flags work as before
./altinity-mcp --read-only  # write_query not registered

# New tools automatically available
# No config needed - split tools are standard
```

### YAML Config (optional future enhancement)

```yaml
# Current (still works)
clickhouse:
  read_only: false

# Future (optional, not needed now)
tools:
  enabled:
    - read_query      # Always safe
    - write_query     # Only if not read_only
    - execute_query   # Deprecated
  
  # Optional: hide deprecated tool
  show_deprecated: false  # Would hide execute_query
```

---

## Documentation Updates

### 1. README.md Changes

```markdown
## Available Tools

### read_query (✨ Recommended)
Execute read-only queries (SELECT, SHOW, DESCRIBE, EXPLAIN).
- Safe to run without confirmation
- Returns up to 10,000 rows
- Examples: Schema exploration, data inspection

### write_query (⚠️ Requires Confirmation)
Execute write operations (INSERT, UPDATE, DELETE, ALTER).
- Always requires user approval
- Cannot be used in read-only mode
- Use carefully to avoid unintended changes

### execute_query (Deprecated)
Auto-routes to read_query or write_query.
- Kept for backwards compatibility
- New integrations should use read_query/write_query
- Will be deprecated in a future version
```

### 2. New Migration Guide

Create `docs/MIGRATION_GUIDE_execute_query.md`:

```markdown
# Migration Guide: execute_query → read_query / write_query

## Why Split Tools?

The split provides:
- Clearer safety semantics (read vs write)
- No unnecessary confirmation for SELECT queries
- Better alignment with ChatGPT and Claude expectations

## Migration Steps

### If you only use SELECT queries:
```python
# OLD
client.call_tool("execute_query", query="SELECT * FROM users")

# NEW
client.call_tool("read_query", query="SELECT * FROM users")
```

### If you only use INSERT/UPDATE/DELETE:
```python
# OLD
client.call_tool("execute_query", query="INSERT INTO users VALUES (...)")

# NEW
client.call_tool("write_query", query="INSERT INTO users VALUES (...)")
```

### If you use both:
```python
# Route based on statement type
if statement_type == "read":
    client.call_tool("read_query", query=query)
else:
    client.call_tool("write_query", query=query)
```

## Timeline

- **Now**: New tools available, execute_query deprecated
- **Next release**: Continued support
- **Future**: Removal decision (TBD based on feedback)
```

---

## Risk Assessment

### Low Risk ✅

- **Backwards compatible**: execute_query still works
- **Opt-in migration**: New tools don't require immediate change
- **Testing**: Comprehensive test coverage
- **Rollback**: Easy to revert if issues found

### Mitigation Strategies

| Risk | Mitigation |
|------|-----------|
| Breaking existing clients | Keep execute_query, deprecate gradually |
| Handler logic complexity | Extract shared logic to executeQueryInternal |
| Statement classification errors | Comprehensive unit tests, fallback to execute_query |
| Performance impact | No additional queries, same client code |
| OpenAPI schema confusion | Clear documentation, separate endpoints |

---

## Success Criteria

### Functional ✅

- [ ] read_query accepts SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS, WITH
- [ ] read_query rejects INSERT, UPDATE, DELETE, ALTER, DROP
- [ ] write_query accepts INSERT, UPDATE, DELETE, ALTER
- [ ] write_query rejects SELECT and other read statements
- [ ] read-only mode: write_query tool not registered
- [ ] execute_query routes correctly to appropriate handler

### Quality ✅

- [ ] Unit test coverage >90%
- [ ] All integration tests pass
- [ ] Backwards compatibility verified
- [ ] No performance regression
- [ ] Deprecation warning logged for execute_query

### User Experience ✅

- [ ] No confirmation prompt for SELECT queries (in Claude)
- [ ] Confirmation prompt for INSERT/UPDATE/DELETE (in Claude)
- [ ] ChatGPT respects x-openai-isConsequential flags
- [ ] OpenAPI schema valid and documented

### Documentation ✅

- [ ] README updated with new tools
- [ ] Migration guide created
- [ ] Tool descriptions clear and comprehensive
- [ ] OpenAPI endpoints documented

---

## Rollout Plan

### Step 1: Code Review
- Review statement classification logic
- Verify handler implementations
- Check OpenAPI schema generation

### Step 2: Internal Testing
- Run full test suite
- Test with real ClickHouse instance
- Verify read-only mode behavior

### Step 3: Beta Release (optional)
- Release to interested users
- Collect feedback
- Fix any issues

### Step 4: Production Release
- Release as minor version
- Announce on GitHub
- Update documentation
- Notify integrations

### Step 5: Post-Release Monitoring
- Watch for issues
- Collect user feedback
- Track execute_query usage
- Plan future removal timeline

---

## Questions for Team Review

Before implementation:

1. **Deprecation Strategy**: Remove execute_query in X releases, or keep indefinitely?
2. **Admin Operations**: Should DROP/TRUNCATE be separate admin_query tool?
3. **Statement Validation**: Any custom SQL dialects to support?
4. **Dynamic Tools**: How should dynamically generated tools be categorized?
5. **Configuration**: Need a way to hide deprecated execute_query?

---

**Implementation Status**: Ready to code  
**Estimated Sprint Story Points**: 13-21 (depending on test requirements)  
**Owner**: [Assigned developer]  
**Reviewer**: [Code reviewer]  
**Target Release**: [Version X.Y.Z]
