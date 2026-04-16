# MCP Tool Standards Research - Summary & Clarifications

**For Issue #35: Split SQL Execution Tools**

---

## Your Questions - Direct Answers

### Q1: "How do I publish MCP tools and announce them properly for different modes?"

**Answer:**

MCP has a **single, unified announcement mechanism** regardless of mode:

1. **At Server Startup**: Send list of tools via `initialize` response
   - Tool definitions include: name, title, description, schema, **annotations**
   - Clients use these to decide tool availability and safety

2. **For Different Modes** (e.g., read-only):
   - **Conditional Registration**: Only register `write_query` if `!cfg.ClickHouse.ReadOnly`
   - **Annotation Changes**: Same tool name but different annotations based on mode
   - **No "modes" announcement**: You don't tell the host "I'm in read-only mode"
   - Instead: **The tools you register implicitly show your mode**

**Example**:
```go
// Mode 1: Normal (read & write capable)
// → Registers: read_query, write_query, (execute_query deprecated)

// Mode 2: Read-Only
// → Registers: read_query, (execute_query deprecated)
// → write_query NOT registered
// → Host automatically knows it can only read
```

---

### Q2: "How do Anthropic and OpenAI positions differ?"

**Answer:**

| Aspect | Anthropic Claude | OpenAI GPTs |
|--------|------------------|------------|
| **Tool Definition** | API parameters (name, description, schema) | OpenAPI spec + extensions |
| **Safety Metadata** | None in spec; uses detailed description | `x-openai-isConsequential` flag |
| **Confirmation** | Custom (Claude Code uses `AskUserQuestion`) | Built-in ChatGPT behavior |
| **Annotation Support** | Doesn't expose MCP annotations in API | Extends OpenAPI with x-fields |
| **Trust Model** | Application-enforced | Contract-based (OpenAPI) |

**Key Difference**:
- **Anthropic**: "Description is everything" - Claude reads description to decide safety
- **OpenAI**: "Flag-based" - Uses x-openai-isConsequential for automatic confirmation

**For altinity-mcp**: You need BOTH approaches:
1. Clear descriptions (Anthropic)
2. MCP annotations (for standard clients)
3. x-openai-isConsequential in OpenAPI (for ChatGPT)

---

### Q3: "What metadata should my MCP server provide for each tool?"

**Answer:**

**Minimum Required**:
```go
type Tool struct {
    Name           string                // "read_query" (lowercase_underscore)
    Title          string                // "Execute Read-Only Query"
    Description    string                // ← Most important for safety!
    InputSchema    map[string]interface{} // JSON Schema for parameters
}
```

**Recommended (for safety)**:
```go
type Tool struct {
    Name           string
    Title          string
    Description    string
    InputSchema    map[string]interface{}
    Annotations    *ToolAnnotations       // ← Add this!
}

type ToolAnnotations struct {
    ReadOnlyHint     bool  // true if no side effects
    DestructiveHint  *bool // true if irreversible
    IdempotentHint   *bool // true if safe to retry
    OpenWorldHint    *bool // true if external API calls
}
```

**Best Practice Description Template**:
```
"[Action] [Allowed Inputs] [Constraints]

Example:
Execute read-only SQL queries (SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS).
Returns up to 10,000 rows in JSON format. 
In read-only mode, only read statements are allowed."
```

---

### Q4: "How do read-only and public expose work?"

**Answer:**

**Read-Only Mode**:
```bash
./altinity-mcp --read-only  # Only SELECT-like tools registered

# Current problem: Single execute_query marked as destructive
# Solution: Split tools
# - read_query: Always registered (safe)
# - write_query: NOT registered in read-only mode
# - execute_query: Deprecated
```

**Public Expose (OpenAPI)**:
```bash
./altinity-mcp --transport http --openapi http

# Available endpoints:
GET  /openapi/schema                    # OpenAPI specification
GET  /{token}/openapi/read_query        # Safe (no confirmation)
POST /{token}/openapi/write_query       # Risky (confirmation)

# OpenAPI specification marks safety:
x-openai-isConsequential: false  # For read_query
x-openai-isConsequential: true   # For write_query
```

**Limitations** (per public expose):
```yaml
# What can be exposed:
✅ read_query        # Safe for public
✅ write_query       # Users confirm
❌ admin_query       # Never expose (DROP, TRUNCATE)

# Authentication for public:
- JWE token in path: /{token}/openapi/...
- OAuth bearer token: Authorization: Bearer {token}
- Per-request credentials: Embedded in token
```

---

### Q5: "Which MCP standards are current for 2026?"

**Answer:**

**Latest Official Standard**: MCP 2025-11-25
- Quad-annotation model (readOnly, destructive, idempotent, openWorld)
- Tool definitions support optional annotations
- Emphasis: **"Annotations are hints, not security boundaries"**

**Industry Adoption** (2026):
- **Anthropic Claude**: Uses descriptions, not annotations (custom safety)
- **OpenAI ChatGPT**: Uses x-openai-isConsequential in OpenAPI specs
- **ClickHouse MCP**: Implements three-tier permission model with annotations
- **StarRocks MCP**: Best-in-class with explicit read/write tool separation

**Recommendation**: Implement **all three**:
1. MCP annotations (for standard MCP clients)
2. Detailed descriptions (for Claude)
3. x-openai-isConsequential (for ChatGPT/OpenAI)

---

## Understanding the Problem (Issue #35)

### Current State
```
Single execute_query tool:
┌─────────────────────────────────┐
│       execute_query             │
├─────────────────────────────────┤
│ Annotations:                    │
│  - DestructiveHint: true        │ ← Problem!
├─────────────────────────────────┤
│ Allowed:                        │
│  - SELECT (read-only)           │ ← Marked as risky
│  - INSERT (write)               │ ← Actually risky
│  - DELETE (write)               │ ← Actually risky
└─────────────────────────────────┘

Result: All queries trigger confirmation
        ❌ User experiences friction
        ❌ Hosts can't distinguish safe from unsafe
        ❌ Violates principle: "dangerous by default"
```

### Proposed Solution
```
Three explicit tools:
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│  read_query        │    │  write_query       │    │ execute_query      │
├────────────────────┤    ├────────────────────┤    ├────────────────────┤
│ ReadOnly: true     │    │ Destructive: true  │    │ DEPRECATED         │
│ Destructive: false │    │ ReadOnly: false    │    │ For compatibility  │
├────────────────────┤    ├────────────────────┤    ├────────────────────┤
│ SELECT             │    │ INSERT             │    │ All statements     │
│ SHOW               │    │ UPDATE             │    │ (subject to mode)  │
│ DESCRIBE           │    │ DELETE             │    │                    │
│ EXPLAIN            │    │ ALTER              │    │                    │
│ EXISTS             │    │                    │    │                    │
│ WITH               │    │                    │    │                    │
└────────────────────┘    └────────────────────┘    └────────────────────┘
  ✅ Safe (no confirm)      ✅ Risky (confirm)      ⚠️  Backwards compat
```

---

## Key Implementation Points

### 1. Server-Side Validation is Critical

**MCP Annotations are NOT Enforced**:
```
❌ Bad: Trust annotation alone
Client: "Server says read-only? I'll skip confirmation"
Server sends: execute_query with DestructiveHint: false
Client: Trusts and skips confirmation
→ But server executes DELETE!

✅ Good: Enforce at server level
Tool handler validates statement:
  if tool == "read_query" {
    classifyStatement(query)
    if !isReadStatement(query) {
      return error("read_query only allows SELECT, etc.")
    }
  }
```

### 2. Statement Classification

Create a function that categorizes SQL statements:

```
SELECT          → Read
WITH            → Read
SHOW            → Read
DESCRIBE        → Read
EXPLAIN         → Read
EXISTS          → Read

INSERT          → Write
UPDATE          → Write
DELETE          → Write
ALTER           → Write

DROP            → Admin (very dangerous)
TRUNCATE        → Admin (very dangerous)
```

### 3. Tool Announcements by Mode

```go
if !config.ReadOnly {
    registerTool("read_query")      // Always
    registerTool("write_query")     // Only in write mode
    registerTool("execute_query")   // Deprecated, backwards compat
}

if config.ReadOnly {
    registerTool("read_query")      // Always safe
    // write_query NOT registered
    registerTool("execute_query")   // For backwards compat
}
```

---

## Public Safety Standards

### What Should Be Public (OpenAPI)?

**Safe to Expose**:
- ✅ `read_query` - No mutation
- ✅ `write_query` - Requires explicit confirmation
- ✅ Schema resources - Metadata only

**Never Expose**:
- ❌ Direct ClickHouse access
- ❌ Admin credentials
- ❌ System settings modification

### Authentication Models for Public

**Option 1: JWE Tokens** (Current altinity-mcp)
```
GET /token123abc/openapi/read_query?query=SELECT...
↓
Server decrypts token → extracts ClickHouse credentials
↓
Executes with those credentials
✅ Works for: Per-tenant isolation, ephemeral access
```

**Option 2: OAuth Bearer** (Also supported)
```
GET /openapi/read_query?query=SELECT...
Authorization: Bearer {oauth_token}
↓
Server validates token → forwards to ClickHouse
✅ Works for: Corporate SSO, token-based auth
```

**Option 3: Server Static Credentials** (Simplest)
```
GET /openapi/read_query?query=SELECT...
↓
Server uses pre-configured ClickHouse credentials
❌ Problem: All users share permissions
```

---

## Checklist: What You Should Ask the Team

Before implementing, clarify:

- [ ] Should `execute_query` be deprecated in this release or hidden?
- [ ] How long backwards compatibility window? (suggest: 2 minor versions)
- [ ] Should read-only mode completely hide write_query? (recommended: yes)
- [ ] Do you need admin_query (DROP/TRUNCATE) as separate tool? (recommended: yes, future)
- [ ] Should statementClassification be pluggable (for custom SQL dialects)?
- [ ] How should dynamic tools be categorized (read vs write)?
- [ ] Should OpenAPI endpoints also split? (recommended: yes)

---

## Key Takeaway

**MCP Annotations** (readOnly, destructive, etc.) are:
- ✅ Informational hints for client UX
- ✅ Good for documentation
- ✅ Useful for host confirmation workflows
- ❌ NOT security boundaries
- ❌ Not enforceable contracts

**Real Security** happens at:
1. **Server-level validation** (check statement type in handler)
2. **Application logic** (refuse to run disallowed queries)
3. **Database permissions** (read-only user account)
4. **Human-in-the-loop** (confirmation dialog for risky operations)

---

## References for Implementation

See the full document for:
- `/docs/MCP_STANDARDS_AND_IMPROVEMENTS.md` - Complete technical details
- Code examples in Go
- OpenAPI specification templates
- Testing strategy
- Deprecation timeline

---

**Next Steps**:
1. Review this summary with the team
2. Clarify the 5 team questions above
3. Proceed with implementation based on full standards document
4. Implement tool splitting first, then deprecation messaging
