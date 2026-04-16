# Remaining Decisions: OpenAPI Endpoints & Tool Hiding

**Based on Team Feedback**

---

## Question 1: Do We Need Separate OpenAPI Endpoints?

### Current Approach (Proposed in Earlier Plan)

```
/openapi/execute_query      ← Read operations
/openapi/write_query        ← Write operations (new)
/openapi/read_query         ← Dynamic read tools
/openapi/dynamic_write_*    ← Dynamic write tools
```

Each endpoint has `x-openai-isConsequential` flag:
```yaml
execute_query:    x-openai-isConsequential: false
write_query:      x-openai-isConsequential: true
read_query:       x-openai-isConsequential: false
```

### Your Question: "Why Change OpenAPI Endpoints?"

**Excellent point.** Let me analyze:

---

## Pro/Cons Analysis

### ❌ CONS: Separate Endpoints (Why NOT Needed)

| Con | Impact | Severity |
|-----|--------|----------|
| **Additional complexity** | More endpoints to maintain | High |
| **Not MCP-related** | MCP tools already separate (via tool list) | High |
| **OpenAI-specific** | Only ChatGPT uses x-openai-isConsequential | Medium |
| **Claude doesn't need it** | Claude uses tool annotations, not OpenAPI flags | Medium |
| **More code** | Multiple endpoint handlers | Low |
| **Potential routing confusion** | Which endpoint for which operation? | Medium |
| **Not essential** | Current single execute_query endpoint works fine | High |

### Example of Unnecessary Duplication

```go
// Current: Works fine
GET /openapi/execute_query?query=SELECT...
POST /openapi/execute_query {query: INSERT...}

// Proposed: More complex
GET /openapi/read_query?query=SELECT...
POST /openapi/write_query {query: INSERT...}

// But MCP tools already handle this!
// Claude knows write_query is destructive via annotations
// ChatGPT also sees tool list + x-openai-isConsequential on tool itself
```

### ✅ PROS: Separate Endpoints (Why MIGHT Help)

| Pro | Impact | Use Case |
|-----|--------|----------|
| **Explicit separation** | OpenAPI schema clearer | GPT integration |
| **Direct tool mapping** | `/write_query` → `write_query` tool | REST API consistency |
| **ChatGPT optimizations** | Can call specific endpoint | If using OpenAPI directly |
| **Future flexibility** | Can add different handlers later | Unknown needs |
| **Discoverable** | Clearer REST API | If GPT docs matter |

---

## Verdict: Keep Current Approach (SIMPLER)

### Current (Recommended)

```
Single endpoint: /openapi/execute_query

Schema shows all tools:
  - execute_query (read-safe)
  - write_query (risky)
  - dynamic_read_* tools
  - dynamic_write_* tools

Each tool in schema has x-openai-isConsequential flag
```

**Why**:
- ✅ Simpler code (1 endpoint handler, not multiple)
- ✅ MCP already separates via tool list
- ✅ OpenAPI flag on tool is sufficient for ChatGPT
- ✅ Claude uses annotations (not OpenAPI)
- ✅ Less maintenance burden
- ✅ Current altinity-mcp pattern

### Current OpenAPI Handler Structure

```go
func (s *ClickHouseJWEServer) OpenAPIHandler(w http.ResponseWriter, r *http.Request) {
    // Route based on tool name in query params or body
    switch toolName {
    case "execute_query":
        // Handle: SELECT/SHOW/etc OR INSERT/UPDATE/DELETE (for compat)
    case "write_query":
        // Handle: INSERT/UPDATE/DELETE/ALTER
    case "read_query", "dynamic_read_*":
        // Handle: SELECT queries
    case "dynamic_write_*":
        // Handle: INSERT queries
    }
}

// No need to split into /read_query /write_query endpoints
// Single /execute_query endpoint routes internally
```

### If Supporting Multiple Endpoints (Future, Not Needed Now)

```go
// Route patterns - optional future enhancement
/openapi/execute_query         // Backwards compat
/openapi/{tool_name}          // Generic: read_query, write_query, etc
/openapi/{dynamic_tool}       // Dynamic tools
```

But this is **not necessary**. One endpoint works fine.

---

## Recommendation

### Keep It Simple ✅

```yaml
# Configuration
server:
  openapi:
    enabled: true
    tls: false

# Endpoints
GET  /openapi              ← Schema discovery
POST /openapi/execute_query ← All operations route here
```

**Why**:
1. MCP tools already separate (tool list, annotations)
2. OpenAPI flag on tool is sufficient
3. Reduces code complexity
4. Current altinity-mcp pattern
5. No downside for Claude or ChatGPT

---

---

## Question 2: How to Hide Static `write_query` Tool?

### Scenario

User wants:
```
✅ Dynamic write tools FROM tables (explicit, schema-validated)
❌ Generic static write_query tool (generic fallback)

Reasoning: 
"If I've configured specific table-based tools, 
I don't need the generic write_query fallback"
```

### Solution: Configuration Option

Add flag to control tool announcement:

```yaml
server:
  tools:
    expose_static_write_query: false    # Hide generic write_query tool
```

### Implementation

**In config:**
```go
type ServerToolsConfig struct {
    ExposeStaticWriteQuery bool `json:"expose_static_write_query" yaml:"expose_static_write_query"`
    // default: true (for backwards compat)
}

type ServerConfig struct {
    Tools *ServerToolsConfig `json:"tools" yaml:"tools"`
}
```

**In RegisterTools():**
```go
func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    // Always register execute_query (read-safe)
    srv.AddTool(executeQueryTool, HandleExecuteQuery)
    
    // Conditionally register write_query
    if cfg.Server.Tools != nil && !cfg.Server.Tools.ExposeStaticWriteQuery {
        // Skip registration
        log.Info().Msg("write_query tool hidden (configured)")
    } else {
        // Register by default
        srv.AddTool(writeQueryTool, HandleWriteQuery)
        log.Info().Msg("write_query tool registered")
    }
    
    // Always register dynamic tools if configured
    // (read and/or write depending on rules)
}
```

### Usage Examples

**Example 1: Hide generic write_query, use only dynamic write tools**
```yaml
server:
  tools:
    expose_static_write_query: false
  
  dynamic_tools:
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"

# Result:
# Tools exposed: execute_query, log_event (dynamic)
# Tools hidden: write_query (generic fallback)
```

**Example 2: Keep both (backwards compat)**
```yaml
server:
  tools:
    expose_static_write_query: true    # default
  
  dynamic_tools:
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"

# Result:
# Tools exposed: execute_query, write_query, log_event
# User can use either generic write_query or specific log_event
```

**Example 3: Default behavior (no config)**
```yaml
server:
  # No tools config specified
  dynamic_tools: []

# Result:
# Tools exposed: execute_query, write_query (default=true)
# Backwards compatible with existing deployments
```

---

## Why This Makes Sense

### Problem It Solves

```
Scenario: Company configures dynamic write tools from their tables

❌ Without hiding option:
   - User sees: execute_query, write_query, log_event, create_user, update_order, ...
   - Confusion: "Should I use write_query or the specific tools?"
   - Claude might pick wrong tool
   - Cluttered tool list

✅ With hiding option:
   - User sees: execute_query, log_event, create_user, update_order, ...
   - Clear: Only use the specific tools (schema-validated)
   - No confusion
   - Clean tool list
```

### Security Benefit

```
✅ Enforces intended schema:
   - Admin configures specific tools
   - By hiding write_query, admin forces use of schema-validated tools
   - No way to bypass validation with generic write_query

❌ Without hiding:
   - User could still call write_query
   - Bypasses schema validation
   - Could execute unintended SQL
```

---

## Configuration in YAML

### Full Example

```yaml
clickhouse:
  host: localhost
  port: 8123

server:
  # New: Control tool exposure
  tools:
    expose_static_write_query: false    # Hide generic write_query tool
  
  # Dynamic tools from tables
  dynamic_tools:
    # Read tools from views
    - type: "read"
      regexp: "analytics\\..*_view"
      prefix: "get_"
    
    # Write tools from tables (INSERT only)
    - type: "write"
      regexp: "^events\\..*_table$"
      prefix: "log_"
      mode: "insert"
    
    - type: "write"
      regexp: "^users\\..*_table$"
      prefix: "create_"
      mode: "insert"

logging:
  level: "info"
```

**Result**:
```
Tools registered:
✅ execute_query                (always, read-safe)
✅ get_daily_stats              (dynamic read from analytics.daily_stats_view)
✅ log_event                    (dynamic write INSERT into events.event_log)
✅ create_user                  (dynamic write INSERT into users.users_table)
❌ write_query                  (hidden, not exposed)
```

---

## Implementation Checklist

### Code Changes (Minimal)

- [ ] Add `ServerToolsConfig` struct to config
- [ ] Add `tools.expose_static_write_query` YAML field
- [ ] Modify `RegisterTools()` to check flag before registering write_query
- [ ] Add logging for hidden tools
- [ ] Update config comments/docs

### No Changes Needed

- ✅ No OpenAPI changes (keep single endpoint)
- ✅ No handler changes
- ✅ No dynamic tool logic changes

### Documentation

- [ ] Add example: "Hide generic tool, use only dynamic tools"
- [ ] Explain security benefit
- [ ] Show both scenarios (hide vs expose)

---

## Default Behavior (Backwards Compatible)

**If config not specified:**
```yaml
# Not mentioned = default behavior
server:
  dynamic_tools: [...]
```

**Behavior:**
```
tools:
  expose_static_write_query: true    # Default = true (backwards compat)
  
Result: All tools exposed (current behavior preserved)
```

**Why**:
- Existing deployments don't break
- Gradual adoption
- Explicit opt-in to hide

---

## Summary Table

| Scenario | Config | Tools Exposed | Use Case |
|----------|--------|---------------|----------|
| **Default** | Not specified | execute_query, write_query, dynamics | Existing deployments |
| **Dynamic only** | expose_static_write_query: false | execute_query, dynamics only | Schema-validated strict |
| **Full control** | expose_static_write_query: true | execute_query, write_query, dynamics | Maximum flexibility |

---

## Final Recommendations

### 1. OpenAPI Endpoints ✅
**Recommendation**: Keep single `/openapi/execute_query` endpoint
- No need for separate endpoints
- MCP tools already separate
- Simpler code, same functionality
- ✅ What you originally proposed was overcomplicated

### 2. Hide Static write_query ✅
**Recommendation**: Add `expose_static_write_query: false` option
- Solves the use case you described
- Simple config flag (1 line)
- Minimal code changes
- Backwards compatible (default: true)
- Makes sense when using schema-validated dynamic tools

---

## Quick Implementation (Both Decisions)

### Code Changes: ~50 lines total

```go
// 1. Config struct (10 lines)
type ServerToolsConfig struct {
    ExposeStaticWriteQuery bool `json:"expose_static_write_query" yaml:"expose_static_write_query"`
}

// 2. RegisterTools() change (10 lines)
func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    srv.AddTool(executeQueryTool, HandleExecuteQuery)
    
    exposeWrite := true  // default
    if cfg.Server.Tools != nil {
        exposeWrite = cfg.Server.Tools.ExposeStaticWriteQuery
    }
    
    if exposeWrite {
        srv.AddTool(writeQueryTool, HandleWriteQuery)
    }
}

// 3. Logging (5 lines)
if exposeWrite {
    log.Info().Msg("write_query tool registered")
} else {
    log.Info().Msg("write_query tool hidden")
}
```

---

**Next Steps:**
1. ✅ Keep single OpenAPI endpoint (no change)
2. ✅ Add `expose_static_write_query` config option
3. Ready to implement!
