# MCP Tool Safety Standards and Altinity-MCP Improvements

**Date**: April 16, 2026  
**Status**: Analysis & Recommendations for Issue #35

---

## Executive Summary

The altinity-mcp server currently exposes a single `execute_query` tool that handles both read and write operations. This violates industry best practices established by ClickHouse and StarRocks MCP servers, and doesn't align with how Anthropic Claude and OpenAI GPTs expect tool safety metadata to be structured.

### Key Findings

1. **MCP Annotations are Optional Hints, Not Security Boundaries**
   - Real security enforcement must happen at the server/application level
   - Annotations inform UI/UX and confirmation flows, but cannot be trusted from untrusted sources

2. **Anthropic Claude and OpenAI GPTs Use Different Safety Models**
   - **Anthropic**: Relies on detailed descriptions + custom approval flows (e.g., `AskUserQuestion`)
   - **OpenAI**: Uses `x-openai-isConsequential` in OpenAPI specifications for ChatGPT confirmations

3. **Industry Best Practice: Read/Write Tool Separation**
   - ClickHouse and StarRocks implement explicit tool splitting
   - Three-tier security model: Read (default) → Write (opt-in) → Destructive (additional opt-in)

4. **Current altinity-mcp Gap**: Issue #35 is blocking proper tool separation because:
   - Single `execute_query` marked as destructive hides read-only operations behind confirmations
   - No server-side validation distinguishing read vs write statements
   - Users experience unnecessary confirmation friction for simple queries

---

## Part 1: MCP Standards and Specifications

### 1.1 Official MCP Tool Annotations

The MCP 2025-11-25 specification defines four optional boolean annotations:

```go
type ToolAnnotations struct {
    ReadOnlyHint     bool  // Tool reads data without modification
    DestructiveHint  *bool // Tool performs irreversible operations (DELETE, DROP, ALTER)
    IdempotentHint   *bool // Calling repeatedly has no additional effect
    OpenWorldHint    *bool // Tool may interact with unpredictable external systems
}
```

**Official MCP Guidance:**
> "For trust & safety and security, clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers."

**Implications**:
- Annotations are *informational hints* for client UX, not enforceable contracts
- Real security must be implemented at the server/application level
- A malicious server can lie about tool safety
- Annotations guide confirmation flows but don't prevent misuse

### 1.2 What Annotations Cannot Do (Per MCP Blog)

The MCP specification blog post "Tool Annotations as Risk Vocabulary" explicitly states annotations **cannot**:

1. **Enforce security guarantees** - They're hints, not barriers
2. **Prevent prompt injection** - A crafted prompt can trick any tool
3. **Stop dishonest servers** - Untrusted servers can misrepresent capabilities
4. **Prevent the "lethal trifecta"** - Combining:
   - Access to private data
   - Exposure to untrusted content  
   - External communication capability
   
   This combination enables data theft regardless of individual tool annotations

### 1.3 MCP Tool Announcement Mechanism

When an MCP server starts:

1. **STDIO Transport**: Sends `initialize` response with tool/resource/prompt list
2. **HTTP/SSE Transport**: Exposes `GET /mcp/list_tools` endpoint
3. **OpenAPI Transport**: Serves OpenAPI schema at `/openapi` with all operations

Clients (Claude, ChatGPT) receive complete tool definitions including:
- Name, title, description
- Input schema (JSON Schema)
- Annotations (optional)

---

## Part 2: Anthropic Claude vs OpenAI Approach

### 2.1 Anthropic Claude Tool Safety Model

**Claude's Approach**: Detailed descriptions + custom approval flows

**Tool Definition Structure** (Claude API):
```go
type Tool struct {
    Name        string         // Tool identifier
    Description string         // Critical for safety guidance
    InputSchema JSONSchema     // Parameter definitions
    InputExamples []Example    // Optional validated examples
    Strict      bool          // Enforce schema validation
}
```

**Key Differences from MCP**:
- ❌ **No built-in annotation field** - Claude API doesn't expose MCP annotations in tool definitions
- ✅ **Description is paramount** - Used to guide Claude's decision-making
- ✅ **Custom approval flows** - Applications like Claude Code use custom tools (e.g., `AskUserQuestion`)
- ✅ **Tool choice control** - API-level parameter controls whether Claude uses tools at all

**Claude Safety Example**:
```python
# Tool definition
tools = [{
    "name": "execute_query",
    "description": "Executes SQL. In read-only mode, only SELECT/WITH/SHOW/DESC/EXISTS/EXPLAIN allowed.",
    "input_schema": {...}
}]

# Tool choice control
response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    tools=tools,
    tool_choice="auto",  # Claude decides
    messages=[...]
)

# Custom confirmation in Claude Code
# Uses AskUserQuestion tool for sensitive operations
```

**Notable**: Claude doesn't enforce read-only restrictions at the API level. Enforcement happens in:
1. Tool description (guidance)
2. Application logic (validation)
3. Custom approval workflows (AskUserQuestion)

---

### 2.2 OpenAI GPT Actions Safety Model

**OpenAI's Approach**: OpenAPI `x-openai-isConsequential` flag for ChatGPT confirmations

**OpenAPI Extension Field**:
```yaml
paths:
  /execute_query:
    post:
      operationId: execute_query
      description: Execute SQL query
      x-openai-isConsequential: true  # Always prompt for confirmation
      parameters:
        - name: query
          in: query
          required: true
          schema:
            type: string
```

**Behavior by Flag Value**:

| Flag Value | Behavior |
|-----------|----------|
| `true` | ChatGPT **always** prompts for user confirmation, no "always allow" button |
| `false` | ChatGPT shows "always allow" button (users can skip future prompts) |
| Not set | Default: GET=false, POST/PUT/DELETE=true |

**Implementation in Altinity-MCP**: When exposing OpenAPI endpoints, this would look like:

```yaml
paths:
  /{token}/openapi/execute_query:
    get:
      operationId: execute_query
      x-openai-isConsequential: true  # Current behavior
```

To support the new split:
```yaml
  /{token}/openapi/read_query:
    get:
      operationId: read_query
      x-openai-isConsequential: false  # No confirmation for safe reads

  /{token}/openapi/write_query:
    post:
      operationId: write_query
      x-openai-isConsequential: true   # Always confirm writes
```

---

### 2.3 Architectural Differences

| Aspect | Anthropic Claude | OpenAI GPT Actions |
|--------|------------------|-------------------|
| **Tool Definition** | Standard API parameters | OpenAPI + extensions |
| **Safety Metadata** | Descriptions only | x-openai-isConsequential flag |
| **Confirmation Mechanism** | Custom (app-controlled) | Built-in ChatGPT behavior |
| **Trust Model** | Application-enforced | OpenAPI contract trust |
| **Default Behavior** | Conservative (asks before changes) | GET safe, mutations risky |

---

## Part 3: Industry Best Practices (ClickHouse, StarRocks)

### 3.1 ClickHouse MCP Server Model

**Three-Tier Progressive Permission Model**:

```bash
# Tier 1: Read-only (default)
./clickhouse-mcp --read-only

# Tier 2: Enable write operations
CLICKHOUSE_ALLOW_WRITE_ACCESS=true ./clickhouse-mcp

# Tier 3: Enable destructive operations
CLICKHOUSE_ALLOW_DROP=true ./clickhouse-mcp
```

**Tool Registration by Tier**:
- **Always present**: `run_query` (readOnlyHint: true by default)
- **With env var**: `run_query` with write permissions
- **With additional flag**: DROP/TRUNCATE operations

**Security Philosophy**: "Default-deny with explicit opt-in for each escalation level"

### 3.2 StarRocks MCP Server Model

**Explicit Tool Separation** (Best-in-class approach):

```go
// Tier 1: Read operations
{
    Name: "read_query",
    Description: "Execute SELECT, SHOW, DESCRIBE, EXPLAIN queries",
    Annotations: &ToolAnnotations{
        ReadOnlyHint: true,
    },
    InputSchema: {...}
}

// Tier 2: Write operations
{
    Name: "write_query",
    Description: "Execute INSERT, UPDATE, DELETE operations",
    Annotations: &ToolAnnotations{
        DestructiveHint: boolPtr(true),
    },
    InputSchema: {...}
}

// Tier 3: DDL operations (when enabled)
{
    Name: "create_table",
    Description: "Create new table (DDL operation)",
    Annotations: &ToolAnnotations{
        DestructiveHint: boolPtr(true),
    },
    InputSchema: {...}
}
```

**Advantages**:
- ✅ Clients announce correct annotations to hosts
- ✅ Hosts can selectively expose safe tools only
- ✅ Clear separation of concerns
- ✅ Progressive capability exposure

---

## Part 4: Gap Analysis - Current Altinity-MCP Implementation

### 4.1 Current State

**What Works**:
- ✅ Single tool `execute_query` with correct annotations
- ✅ Respects `--read-only` flag at server startup
- ✅ OpenAPI endpoints for GPT integration
- ✅ JWE authentication with per-request credentials

**What's Missing** (Issue #35):
- ❌ No tool splitting (read vs write)
- ❌ No server-side SQL statement validation
- ❌ Single tool marked as destructive even for SELECT queries
- ❌ No conditional tool announcement based on read-only mode
- ❌ Unclear annotation semantics to hosts

### 4.2 Problem Manifestation

**Scenario 1: Claude using altinity-mcp**
```
User: "Show me the first 10 rows of the users table"
↓
Claude calls execute_query with "SELECT * FROM users LIMIT 10"
↓
execute_query marked as destructive=true
↓
Claude Code asks for confirmation (unnecessary!)
↓
User frustration: "This is just a SELECT query..."
```

**Scenario 2: ChatGPT using OpenAPI**
```
User: "What's in the events table?"
↓
ChatGPT calls POST /openapi/execute_query?query=SELECT...
↓
x-openai-isConsequential=true
↓
ChatGPT: "I need your approval before running this query"
↓
User sees same confirmation for harmless read
```

### 4.3 Impact Assessment

| User Type | Impact | Severity |
|-----------|--------|----------|
| **Claude Code users** | Unnecessary confirmation prompts degrade UX | Medium |
| **ChatGPT users** | Same - confirmation friction | Medium |
| **Automated workflows** | May require manual approval for read operations | High |
| **Read-only deployments** | Cannot express "read-safe" to clients | High |
| **Compliance audits** | Unclear security posture (annotations vs enforcement) | Medium |

---

## Part 5: Recommended Solution (Issue #35 Implementation)

### 5.1 Overview

Implement **tool splitting with three safety levels**:

```
Level 1: read_query (safe, no confirmation)
         └─ SELECT, WITH, SHOW, DESC, EXPLAIN, EXISTS

Level 2: write_query (risky, confirmation)
         └─ INSERT, UPDATE, DELETE, ALTER TABLE, CREATE TABLE

Level 3: [Future] admin_query (very risky, locked by default)
         └─ DROP TABLE, DROP DATABASE, TRUNCATE
```

### 5.2 Tool Definitions

```go
// Level 1: Safe read operations
readQueryTool := &mcp.Tool{
    Name:  "read_query",
    Title: "Execute Read-Only Query",
    Description: "Execute safe read-only SQL queries (SELECT, SHOW, DESCRIBE, EXPLAIN).",
    Annotations: &mcp.ToolAnnotations{
        ReadOnlyHint:    true,
        DestructiveHint: boolPtr(false),
    },
    InputSchema: {...}
}

// Level 2: Write operations (destructive)
writeQueryTool := &mcp.Tool{
    Name:  "write_query",
    Title: "Execute Write Query",
    Description: "Execute write operations (INSERT, UPDATE, DELETE, ALTER). Always confirm changes.",
    Annotations: &mcp.ToolAnnotations{
        ReadOnlyHint:    false,
        DestructiveHint: boolPtr(true),
    },
    InputSchema: {...}
}

// Legacy tool for backwards compatibility (deprecated)
executeQueryTool := &mcp.Tool{
    Name:  "execute_query",
    Title: "[Deprecated] Execute Query",
    Description: "Deprecated. Use read_query or write_query instead.",
    Annotations: makeExecuteQueryAnnotations(cfg.ClickHouse.ReadOnly),
    InputSchema: {...}
    // Add deprecation hint in description
}
```

### 5.3 Server-Side Validation

**Implement Query Statement Classification**:

```go
// Statement types
const (
    StatementRead = iota
    StatementWrite
    StatementAdmin
    StatementUnknown
)

func classifyStatement(query string) int {
    // Remove comments
    query = removeComments(query)
    trimmed := strings.TrimSpace(strings.ToUpper(query))
    
    // Read operations: SELECT, WITH, SHOW, DESC(RIBE), EXPLAIN, EXISTS
    readPatterns := []string{"SELECT", "WITH", "SHOW", "DESC", "EXPLAIN", "EXISTS"}
    for _, pattern := range readPatterns {
        if strings.HasPrefix(trimmed, pattern) {
            return StatementRead
        }
    }
    
    // Write operations: INSERT, UPDATE, DELETE, ALTER
    writePatterns := []string{"INSERT", "UPDATE", "DELETE", "ALTER"}
    for _, pattern := range writePatterns {
        if strings.HasPrefix(trimmed, pattern) {
            return StatementWrite
        }
    }
    
    // Admin operations: DROP, TRUNCATE, CREATE (certain types)
    adminPatterns := []string{"DROP", "TRUNCATE"}
    for _, pattern := range adminPatterns {
        if strings.HasPrefix(trimmed, pattern) {
            return StatementAdmin
        }
    }
    
    return StatementUnknown
}

func isStatementAllowed(stmt string, toolName string, readOnlyMode bool) error {
    classification := classifyStatement(stmt)
    
    switch toolName {
    case "read_query":
        if classification != StatementRead {
            return fmt.Errorf("read_query only allows SELECT, WITH, SHOW, DESC, EXPLAIN, EXISTS statements")
        }
    
    case "write_query":
        if readOnlyMode {
            return fmt.Errorf("write_query is disabled in read-only mode")
        }
        if classification == StatementRead {
            return fmt.Errorf("write_query does not allow read operations; use read_query instead")
        }
        if classification == StatementAdmin {
            return fmt.Errorf("write_query does not allow admin operations (DROP, TRUNCATE)")
        }
    
    case "execute_query":
        // Legacy - allows everything within read-only constraint
        if readOnlyMode && classification != StatementRead {
            return fmt.Errorf("read-only mode: only read operations allowed")
        }
    }
    
    return nil
}
```

### 5.4 Tool Registration Logic

```go
func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    // Always register read_query
    readQueryTool := &mcp.Tool{
        Name:        "read_query",
        Title:       "Execute Read-Only Query",
        Description: "Execute SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, EXISTS queries",
        Annotations: &mcp.ToolAnnotations{
            ReadOnlyHint:    true,
            DestructiveHint: boolPtr(false),
        },
        InputSchema: readQuerySchema(),
    }
    srv.AddTool(readQueryTool, HandleReadQuery)
    
    // Register write_query only if not in read-only mode
    if !cfg.ClickHouse.ReadOnly {
        writeQueryTool := &mcp.Tool{
            Name:        "write_query",
            Title:       "Execute Write Query",
            Description: "Execute INSERT, UPDATE, DELETE, ALTER operations",
            Annotations: &mcp.ToolAnnotations{
                ReadOnlyHint:    false,
                DestructiveHint: boolPtr(true),
            },
            InputSchema: writeQuerySchema(),
        }
        srv.AddTool(writeQueryTool, HandleWriteQuery)
    }
    
    // Register legacy execute_query for backwards compatibility
    executeQueryTool := &mcp.Tool{
        Name:        "execute_query",
        Title:       "[Deprecated] Execute Query",
        Description: "[DEPRECATED: Use read_query or write_query] Execute SQL queries with automatic routing",
        Annotations: makeExecuteQueryAnnotations(cfg.ClickHouse.ReadOnly),
        InputSchema: executeQuerySchema(),
    }
    srv.AddTool(executeQueryTool, HandleExecuteQuery)
    
    toolsRegistered := 2 // read_query + execute_query
    if !cfg.ClickHouse.ReadOnly {
        toolsRegistered++ // write_query
    }
    
    log.Info().
        Int("tool_count", toolsRegistered).
        Bool("read_only_mode", cfg.ClickHouse.ReadOnly).
        Msg("ClickHouse tools registered")
}
```

### 5.5 OpenAPI Endpoint Changes

**Current**:
```
GET  /{token}/openapi/execute_query?query=...
POST /{token}/openapi/execute_query (body: {query, limit})
```

**New**:
```
# Read operations (safe)
GET  /{token}/openapi/read_query?query=...&limit=...
     x-openai-isConsequential: false

# Write operations (risky)
POST /{token}/openapi/write_query (body: {query, limit})
     x-openapi-isConsequential: true

# Legacy (deprecated)
GET  /{token}/openapi/execute_query?query=...&limit=...
POST /{token}/openapi/execute_query (body: {query, limit})
```

### 5.6 Configuration Changes

```yaml
# config.yaml
clickhouse:
  read_only: false

server:
  # New: Control which tools are exposed
  exposed_tools:
    - read_query              # Always enabled
    - write_query             # Only if !read_only
    - execute_query           # Deprecated, for backwards compat
```

---

## Part 6: Implementation Checklist

### Phase 1: Code Changes
- [ ] Add `classifyStatement()` function for statement validation
- [ ] Create `HandleReadQuery()` and `HandleWriteQuery()` handlers
- [ ] Update `RegisterTools()` to conditionally register tools
- [ ] Add server-side validation in handlers
- [ ] Update OpenAPI schema generation for new endpoints
- [ ] Maintain backwards compatibility with `execute_query`

### Phase 2: Testing
- [ ] Unit tests for statement classification
- [ ] Handler tests for read_query with various statements
- [ ] Handler tests for write_query with various statements
- [ ] Test read-only mode prevents write_query registration
- [ ] OpenAPI schema validation
- [ ] Integration tests with Claude and ChatGPT

### Phase 3: Documentation
- [ ] Update README.md with new tool descriptions
- [ ] Create migration guide for users
- [ ] Document deprecation timeline for execute_query
- [ ] Add tool annotation explanations
- [ ] Document statement allowlist for each tool

### Phase 4: Deployment
- [ ] Release in minor version (not patch)
- [ ] Deprecation notice in CHANGELOG
- [ ] Notification to existing integrations
- [ ] 2-release deprecation window before removing execute_query

---

## Part 7: Metadata and Annotation Best Practices

### 7.1 Tool Metadata Template

Every MCP tool should include:

```go
type Tool struct {
    // Required
    Name  string // lowercase_with_underscores, max 64 chars
    Title string // "Capitalize Each Word", clear action
    
    // Required - most important for safety
    Description string // Detailed, plaintext, explains:
                        // 1. What the tool does
                        // 2. Its constraints (e.g., read-only mode)
                        // 3. Expected inputs and outputs
                        // 4. Common errors
    
    // Required
    InputSchema JSONSchema // JSON Schema for parameters
    
    // Optional but recommended for safety
    Annotations *ToolAnnotations {
        ReadOnlyHint    bool  // true if tool only reads
        DestructiveHint *bool // true if irreversible
        IdempotentHint  *bool // true if safe to retry
        OpenWorldHint   *bool // true if accesses external systems
    }
}
```

### 7.2 Description Best Practices

**Good**:
```
"Execute read-only SQL queries (SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS). 
Returns results in JSON format. Limited to 10,000 rows by default. 
In read-only mode, only these statement types are allowed."
```

**Bad**:
```
"Runs SQL queries and returns JSON results."
```

### 7.3 Annotation Rules

**Rule 1: ReadOnlyHint**
- Set `true` if the tool cannot possibly modify data
- Default to `false` unless certain

**Rule 2: DestructiveHint**
- Set `true` if tool can drop/delete/truncate data
- Use `boolPtr(true)` for explicit true
- Use `nil` if uncertain or mixed

**Rule 3: IdempotentHint**
- Set `true` if `f(x) == f(f(x))`
- Example: Setting a variable to a value is idempotent
- SELECT queries are idempotent (no side effects)

**Rule 4: OpenWorldHint**
- Set `true` if tool makes external API calls
- Set `false` for closed-system tools (databases)
- Especially important for LLM safety

### 7.4 Read-Only vs Write Semantics

**READ_QUERY Annotations**:
```go
Annotations: &mcp.ToolAnnotations{
    ReadOnlyHint:    true,
    DestructiveHint: boolPtr(false),
    IdempotentHint:  boolPtr(true),
    OpenWorldHint:   boolPtr(false),
}
```

**WRITE_QUERY Annotations**:
```go
Annotations: &mcp.ToolAnnotations{
    ReadOnlyHint:    false,
    DestructiveHint: boolPtr(true),
    IdempotentHint:  boolPtr(false),
    OpenWorldHint:   boolPtr(false),
}
```

---

## Part 8: Timeline and Deprecation Strategy

### Version X.Y.Z (Current)
- Release read_query and write_query as new tools
- Keep execute_query with deprecation notice
- Update documentation

### Version X.Y+1.Z (Next Minor)
- execute_query still available
- Deprecation warnings in logs

### Version X.Y+2.Z (Next Minor)
- Consider removing execute_query (or keep for long-term compatibility)
- Announce timeline clearly

**Rationale**: 2-release window allows existing integrations to migrate without breaking

---

## Summary Table: Tool Metadata by Type

| Metadata | read_query | write_query | execute_query (deprecated) |
|----------|-----------|------------|---------------------------|
| **Name** | read_query | write_query | execute_query |
| **ReadOnlyHint** | true | false | config.ClickHouse.ReadOnly |
| **DestructiveHint** | false | true | !config.ClickHouse.ReadOnly |
| **IdempotentHint** | true | false | depends on query |
| **OpenWorldHint** | false | false | false |
| **Statements Allowed** | SELECT, SHOW, DESC, EXPLAIN, WITH, EXISTS | INSERT, UPDATE, DELETE, ALTER | All (subject to read-only mode) |
| **In Read-Only Mode** | Registered | NOT registered | Registered |
| **OpenAPI Safe** | yes (GET, no confirm) | no (POST, confirm) | no (confirm) |

---

## References

1. **MCP Specification 2025-11-25**
   - https://modelcontextprotocol.io/specification/2025-11-25
   - Tool annotation specification and semantics

2. **MCP Blog: Tool Annotations as Risk Vocabulary**
   - https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/
   - Limitations and trust model

3. **Claude API Documentation**
   - https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools
   - Tool definition and safety approach

4. **OpenAI GPT Actions Documentation**
   - https://platform.openai.com/docs/actions/production
   - x-openai-isConsequential specification

5. **ClickHouse MCP Server**
   - https://github.com/ClickHouse/mcp-clickhouse
   - Reference implementation with three-tier model

6. **StarRocks MCP Server**
   - https://github.com/StarRocks/mcp-server-starrocks
   - Best-in-class tool separation example

---

**Document Version**: 1.0  
**Last Updated**: April 16, 2026  
**Status**: Ready for Implementation
