# Design Decisions for Issue #35 & Dynamic Write Tools

**User Feedback Integration**: April 16, 2026

---

## Decision 1: Keep `execute_query` Forever (No Deprecation)

### Decision
- Keep `execute_query` as permanent, read-safe tool
- Do NOT deprecate
- No migration burden for existing integrations

### Rationale
- Altinity-MCP is production software
- Backwards compatibility > aesthetics
- `execute_query` is accurate name (executes queries)
- New users can use `write_query` for clarity

### Benefits
- ✅ Zero breaking changes
- ✅ Simplifies changelog
- ✅ Integrations keep working
- ✅ No migration guide needed

### What Changes
```
BEFORE (no separate tool):
execute_query  → SELECT, INSERT, DELETE (all marked destructive)

AFTER:
execute_query  → SELECT, SHOW, DESC, EXPLAIN, etc. (safe, read-only)
                 Also accepts INSERT, UPDATE, DELETE for compatibility
write_query    → INSERT, UPDATE, DELETE, ALTER (new, explicit)
```

---

## Decision 2: No DROP/TRUNCATE Tools (RBAC Instead)

### Decision
- Do NOT create admin_query or drop_query tools
- Rely entirely on ClickHouse RBAC
- Use role-based access control at database level

### Rationale
**ClickHouse RBAC is better suited because:**

1. **Granularity**
   ```sql
   -- Tool approach (insufficient):
   -- "User can call admin_query tool" = can do anything
   
   -- RBAC approach (precise):
   GRANT DROP ON app_data.cache_table TO user1    -- Specific table
   REVOKE DROP ON app_data.events_table FROM user1 -- Protect critical data
   ```

2. **Consistency**
   ```
   INSERT permission:  Checked by RBAC
   UPDATE permission:  Checked by RBAC
   DROP permission:    Checked by RBAC
   
   All at same enforcement layer = predictable, auditable
   ```

3. **Prevents Tool Proliferation**
   - No admin_query, drop_query, truncate_query, create_query, etc.
   - Each new operation = new tool = context bloat
   - RBAC handles all in one place

4. **Clear Boundary**
   ```
   MCP Tools = Data manipulation (SELECT, INSERT, UPDATE, DELETE)
   Database RBAC = Access control (which operations allowed)
   Database Admin = Direct DB access (for DDL/DCL)
   ```

### Benefits
- ✅ Lean tool set
- ✅ Secure by design (access at DB level)
- ✅ Scalable (works for any operation)
- ✅ Audit trail in ClickHouse logs
- ✅ No false security (tool can't grant what DB denies)

### RBAC Configuration Example
```sql
-- Read-only user
CREATE USER readonly_user IDENTIFIED BY 'password';
GRANT SELECT ON database.* TO readonly_user;

-- Analytics user (read + insert)
CREATE USER analytics_user IDENTIFIED BY 'password';
GRANT SELECT, INSERT ON analytics.* TO analytics_user;

-- Admin user (everything except drop)
CREATE USER app_admin IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE, DELETE, ALTER ON app_data.* TO app_admin;

-- Full admin (only for ops team)
CREATE USER full_admin IDENTIFIED BY 'password';
GRANT ALL ON *.* TO full_admin;
```

---

## Decision 3: Add Dynamic Write Tools from Tables

### Decision
- Extend dynamic tools to support tables (not just views)
- Auto-generate write_query tools from ClickHouse tables
- Support INSERT mode (and optionally UPDATE)
- Exclude alias, materialized, and virtual columns

### Rationale

**Why Add Dynamic Write Tools?**

1. **Consistency with Read Tools**
   ```
   Read tools (views):
   - SELECT * FROM analytics.daily_report_view(date) → user_activity tool
   
   Write tools (tables):
   - INSERT INTO events.event_log (...) → log_event tool
   
   Both driven by same config-as-code approach
   ```

2. **Reduces Boilerplate**
   ```
   ❌ Without dynamic write tools:
      User must call generic write_query
      → write_query(query="INSERT INTO event_log VALUES ('user', 'action')")
      → No validation, error messages unclear
   
   ✅ With dynamic write tools:
      User calls log_event(user='user', action='action')
      → Typed parameters, clear validation, friendly errors
   ```

3. **Enforces Schema Compliance**
   ```
   Tool parameter = table column
   Column definition = validation rules
   
   Tool ensures:
   - Only valid columns accepted
   - Type matching (String vs UInt32)
   - No data leakage
   ```

### What Gets Generated

```
Table: events.event_log
Columns: id (Int64), user_id (String), action (String), timestamp (DateTime)

Dynamic Tool Generated:
Name: log_event
Type: write_query (INSERT)
Parameters:
  - user_id: String (required)
  - action: String (required)
  - timestamp: DateTime (optional, defaults to NOW())

Generated Query:
INSERT INTO events.event_log (user_id, action, timestamp) 
VALUES ('user123', 'login', NOW())
```

### Column Filtering Rules

**INCLUDE**:
```
Normal table columns
Column type: regular (ColumnType='normal')
```

**EXCLUDE**:
```
Alias columns          (ColumnType='alias')
Materialized columns   (ColumnType='materialized')
Virtual columns        (ColumnType='virtual')
Auto-default columns   (DefaultKind='MATERIALIZED'|'ALIAS')
```

**WHY?**
- Alias/materialized/virtual: Computed by ClickHouse, don't accept input
- Auto-default: User provides input, ClickHouse computes value

---

## Decision 4: Keep Tool Definitions Lean

### Decision
- Only create tools that serve explicit user needs
- Don't pre-create tools "just in case"
- Use regex rules for discovery (not catch-all defaults)
- Minimize context bloat

### Rationale

**Tool Proliferation Problem:**
```
100 ClickHouse tables = 100 potential write tools
50 views = 50 potential read tools
= 150 MCP tools advertised to Claude/ChatGPT
= massive context bloat
= slow tool discovery
= user confusion
```

**Lean Approach:**
```
# Only explicit rules create tools
dynamic_tools:
  # Read: Only matching views become tools
  - type: "read"
    regexp: "analytics\\..*_view"
    prefix: "get_"
  
  # Write: Only matching tables become tools
  - type: "write"
    regexp: "events\\..*_table"
    prefix: "log_"
    mode: "insert"

# Tables/views not matching rules = not exposed
# System tables = never exposed
# User has control
```

### Benefits
- ✅ Small, manageable tool set
- ✅ Fast tool discovery
- ✅ Better client performance
- ✅ Clear intent (admin defines what's exposed)
- ✅ Security through explicitness

---

## Decision 5: Configuration Structure with Type + Mode

### Decision
```yaml
DynamicToolRule:
  type: "read" | "write"      # Tool kind
  mode: "insert" | "update"   # For write tools
  name: "explicit_name"       # Optional, for single-view rules
  regexp: "database\\..*"     # Required, for multi-view rules
  prefix: "prefix_"           # For name generation
```

### Why This Structure?

**Flexibility for Different Use Cases:**

```yaml
# Case 1: One-off explicit tool
- type: "read"
  name: "daily_report"
  regexp: "analytics\\.daily_report_view"

# Case 2: Bulk discovery with pattern
- type: "write"
  regexp: "^events\\..*"
  prefix: "log_"
  mode: "insert"

# Case 3: Separate insert/update tools
- type: "write"
  regexp: "users\\..*"
  prefix: "create_"
  mode: "insert"

- type: "write"
  regexp: "users\\..*"
  prefix: "modify_"
  mode: "update"
```

**Why Type + Mode Together?**
- Clear semantics: type="write" + mode="insert"
- Extensible: mode can be "upsert" later
- Audit trail: config shows intent

---

## Decision 6: Static Write Tool: `write_query`

### Decision
```
Static Tools:
├── execute_query      → Safe (SELECT, SHOW, DESCRIBE, etc.)
└── write_query        → Risky (INSERT, UPDATE, DELETE, ALTER)

Dynamic Tools:
├── Read tools         → From views
└── Write tools        → From tables
```

### Tool Annotations

```go
execute_query:
  ReadOnlyHint:    true
  DestructiveHint: false

write_query:
  ReadOnlyHint:    false
  DestructiveHint: true

Dynamic Read Tools:
  ReadOnlyHint:    true
  DestructiveHint: false

Dynamic Write Tools:
  ReadOnlyHint:    false
  DestructiveHint: true
```

### Read-Only Mode Behavior

```yaml
Mode: read_only: true

Registered Tools:
  ✅ execute_query       (read-only operations safe)
  ✅ dynamic read tools  (views, safe)
  ❌ write_query         (not registered, write disabled)
  ❌ dynamic write tools (not registered, write disabled)

User Tries: call write_query
Result: Tool not found / Not available
```

---

## Decision 7: Dynamic Tools Code Organization

### File Structure

**Current**: Everything in `server.go`

**Proposed**: Separate concerns
```
pkg/server/
├── server.go                    (static tools, MCP setup)
├── dynamic_tools.go             (discovery & registration)
├── dynamic_tools_discovery.go   (table/view/column queries)
├── dynamic_tools_handlers.go    (query building, execution)
└── ...
```

### Why?
- Readability (each file < 400 lines)
- Maintainability (concerns separated)
- Testability (isolated functions)
- Scalability (easier to extend)

---

## Design Principles Summary

| Principle | Decision | Why |
|-----------|----------|-----|
| **Backwards Compatibility** | Keep execute_query forever | Stability > aesthetics |
| **Security Model** | RBAC at DB level, not in tools | Better enforcement, no false security |
| **Tool Proliferation** | Keep tools lean, config-driven | Prevent context bloat |
| **Naming Clarity** | write_query (standard) | Industry standard, clear intent |
| **Discovery** | Explicit regex rules, not defaults | Admin has control |
| **Code Organization** | Modular with separated files | Maintainability |
| **Column Filtering** | Exclude computed columns | Only accept user input |

---

## Implementation Order

### Phase 1: Foundation
1. Update config types (DynamicToolRule, dynamicToolMeta)
2. Extract read tool discovery to separate function
3. Create basic test structure

### Phase 2: Dynamic Write Tools
1. Implement table discovery (system.columns query)
2. Implement column filtering logic
3. Implement write query building
4. Implement write tool handlers

### Phase 3: Static Tools (Minimal)
1. Add write_query static tool
2. Ensure read-only mode prevents registration

### Phase 4: Polish
1. Comprehensive testing
2. Documentation
3. Examples

---

## Open Questions for Team

Before starting implementation:

1. **Write Query Complexity**
   - INSERT only for now? (recommended)
   - UPDATE later? (needs WHERE clause handling)
   - UPSERT? (INSERT + UPDATE combined)

2. **Required Parameters**
   - Columns with DEFAULT should be required or optional?
   - Currently: optional (user can omit)

3. **Column Metadata**
   - Include column comments in tool parameter descriptions?
   - Or just ClickHouse type?

4. **Error Messages**
   - Detailed (show all validation errors) or brief?
   - Recommend INSERT vs UPDATE in errors?

5. **Audit Logging**
   - Log tool metadata at startup?
   - Log each write_query execution?

---

## Success Criteria

### Functional ✅
- [ ] execute_query works as read-safe tool
- [ ] write_query handles INSERT, UPDATE, DELETE, ALTER
- [ ] Dynamic read tools from views work (existing)
- [ ] Dynamic write tools from tables work (new)
- [ ] Read-only mode disables write tools
- [ ] RBAC enforced at ClickHouse level

### Quality ✅
- [ ] Unit test coverage >85%
- [ ] No performance regression
- [ ] Clean code (< 400 lines per file)
- [ ] Documented examples

### User Experience ✅
- [ ] Clear error messages
- [ ] Intuitive tool names
- [ ] Schema validation helpful
- [ ] Configuration examples clear

---

**Document Status**: Final decision framework  
**Review**: Approved by user for implementation  
**Owner**: [Development team]  
**Target Start**: [Date]
