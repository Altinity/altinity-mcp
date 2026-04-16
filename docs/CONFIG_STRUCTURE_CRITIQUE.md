# Configuration Structure Critique

## Proposal: Unified `tools` Config for Static + Dynamic

```yaml
server:
  tools:
    # Static tool: explicit definition
    - type: "write"
      name: "write_query"
    
    # Dynamic tools: regex-based discovery
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"
```

---

## Current Approach (Flag-Based)

```yaml
server:
  tools:
    expose_static_write_query: false
  
  dynamic_tools:
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"
```

**Problems it has:**
- ❌ Two separate config sections (tools vs dynamic_tools)
- ❌ Static tools not in config (hardcoded in code)
- ❌ Special-case logic for hiding static tools
- ❌ Inconsistent structure
- ❌ Hard to see what tools are actually exposed

---

## Proposed Approach (Unified Config)

```yaml
server:
  tools:
    # Static tools
    - type: "read"
      name: "execute_query"
      # No regexp (static, not discovered)
    
    - type: "write"
      name: "write_query"
    
    # Dynamic read tools
    - type: "read"
      regexp: "analytics\\..*_view"
      prefix: "get_"
    
    # Dynamic write tools
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"
```

**Advantages:**
- ✅ Single, unified config section
- ✅ Explicit what tools are exposed
- ✅ Config-as-code for everything
- ✅ No special-case code for static tools
- ✅ Easy to add/remove/customize static tools
- ✅ Clear visual hierarchy

---

## Detailed Pro/Cons Analysis

### ✅ PROS

| Pro | Benefit | Use Case |
|-----|---------|----------|
| **Config-as-code** | All tools defined in config, not code | Deploy-time control |
| **Explicit registration** | See exactly what tools are active | Debugging, documentation |
| **Single source of truth** | One `tools` section, not scattered | Maintainability |
| **Unified processing** | Same code handles static/dynamic | Less code |
| **Easy customization** | Override tool names per environment | Multi-environment setup |
| **Clear visibility** | DevOps can see what tools are enabled | Infrastructure as code |
| **No special casing** | Static tools = just another entry | Simpler code logic |
| **Extensible** | Add more static tools easily | Future expansion |
| **Documentation** | Config file shows system capabilities | Self-documenting |

### ❌ CONS

| Con | Impact | Severity |
|-----|--------|----------|
| **More config entries** | Longer YAML for static tools | Low |
| **Backwards compat** | Existing configs don't have this | High |
| **Default handling** | What if user doesn't define tools? | Medium |
| **Static vs dynamic logic** | Different processing paths | Medium |
| **Validation complexity** | Must validate entries correctly | Medium |
| **Documentation burden** | Need to explain both types clearly | Low |

---

## Comparison Table

| Aspect | Current (Flag) | Proposed (Unified) |
|--------|----------------|-------------------|
| **Config sections** | 2 (tools, dynamic_tools) | 1 (tools) |
| **Static tools in config** | No (hardcoded) | Yes ✅ |
| **Can customize tool names** | No | Yes ✅ |
| **Can hide static tools** | Flag (expose_*) | Just don't list ✅ |
| **Lines of YAML** | ~5 for flag, ~10 for dynamics | ~15-20 for all |
| **Code complexity** | Less | More |
| **Clarity** | Moderate | Excellent ✅ |
| **Backwards compat** | Good ✅ | Needs migration |
| **Extensibility** | Limited | Excellent ✅ |

---

## Implementation Comparison

### Current Approach (Flag-Based)

```go
type ServerToolsConfig struct {
    ExposeStaticWriteQuery bool `json:"expose_static_write_query"`
}

func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    // execute_query always
    srv.AddTool(executeQueryTool, HandleExecuteQuery)
    
    // write_query conditional on flag
    if cfg.Server.Tools.ExposeStaticWriteQuery {
        srv.AddTool(writeQueryTool, HandleWriteQuery)
    }
    
    // Dynamic tools separate logic
    srv.EnsureDynamicTools(ctx)
}
```

**Lines of code**: ~20-30  
**Special cases**: 1 (write_query flag)

---

### Proposed Approach (Unified Config)

```go
type ToolDefinition struct {
    Type      string `json:"type"`      // "read", "write"
    Name      string `json:"name"`      // Static tool name (optional, if no regexp)
    Regexp    string `json:"regexp"`    // Dynamic discovery pattern (optional)
    Prefix    string `json:"prefix"`    // Tool prefix for discovered tools
    Mode      string `json:"mode"`      // "insert", "update" for writes
}

func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    for _, toolDef := range cfg.Server.Tools {
        if toolDef.Regexp == "" {
            // Static tool (has name, no regexp)
            registerStaticTool(srv, toolDef)
        } else {
            // Dynamic tool (has regexp)
            registerDynamicToolRule(srv, toolDef)
        }
    }
}

func registerStaticTool(srv AltinityMCPServer, def ToolDefinition) {
    switch def.Type {
    case "read":
        if def.Name == "execute_query" {
            srv.AddTool(executeQueryTool, HandleExecuteQuery)
        } else {
            // Custom read tool
        }
    case "write":
        if def.Name == "write_query" {
            srv.AddTool(writeQueryTool, HandleWriteQuery)
        } else {
            // Custom write tool
        }
    }
}
```

**Lines of code**: ~40-60  
**Special cases**: 0 (unified handling)  
**Flexibility**: Much higher

---

## Real-World Configuration Examples

### Example 1: Minimal (Everything Default)

**Current approach:**
```yaml
server:
  # Use defaults (execute_query + write_query always)
  dynamic_tools: []
```

**Proposed approach:**
```yaml
server:
  tools:
    # Nothing: rely on code defaults?
    # OR explicitly list:
    - type: "read"
      name: "execute_query"
    - type: "write"
      name: "write_query"
```

**Question**: What's the default if config is empty?

---

### Example 2: Hide Static, Use Only Dynamic

**Current approach:**
```yaml
server:
  tools:
    expose_static_write_query: false
  
  dynamic_tools:
    - type: "write"
      regexp: "events\\..*"
      prefix: "log_"
      mode: "insert"
```

**Proposed approach:**
```yaml
server:
  tools:
    # Only list what you want
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      regexp: "events\\..*"
      prefix: "log_"
      mode: "insert"
```

**Better**: Simpler and clearer! ✅

---

### Example 3: Complex Setup with Custom Tools

**Current approach:**
```yaml
server:
  tools:
    expose_static_write_query: true
  
  dynamic_tools:
    - type: "read"
      regexp: "analytics\\..*_view"
      prefix: "get_"
    
    - type: "write"
      regexp: "events\\..*"
      prefix: "log_"
```

**Proposed approach:**
```yaml
server:
  tools:
    # Static tools
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    # Custom static tool
    - type: "read"
      name: "admin_query"
      # Special admin query tool
    
    # Dynamic tools
    - type: "read"
      regexp: "analytics\\..*_view"
      prefix: "get_"
    
    - type: "write"
      regexp: "events\\..*"
      prefix: "log_"
      mode: "insert"
```

**Clearer**: All tools visible in one place ✅

---

## Backwards Compatibility Solution

### Migration Path

**Phase 1: Keep both (support old + new)**
```go
// Old config (still works)
server:
  tools:
    expose_static_write_query: false
  dynamic_tools:
    - type: "write"
      regexp: "events\\..*"

// New config (also works)
server:
  tools:
    - type: "write"
      name: "write_query"
    - type: "write"
      regexp: "events\\..*"
```

**Phase 2: Warn about old config**
```
Log warning: "dynamic_tools config is deprecated, use tools instead"
```

**Phase 3: Remove old config**
```
Only support: tools (all static + dynamic)
```

---

## Key Decision: How to Handle Defaults?

### Question: What if user doesn't define tools config?

**Option A: Use code defaults**
```yaml
server:
  # Empty/missing tools config
  # Automatically register: execute_query, write_query
```

**Option B: Require explicit config**
```yaml
server:
  tools:
    - type: "read"
      name: "execute_query"
    - type: "write"
      name: "write_query"
```

**Option C: Hybrid**
```yaml
server:
  tools:
    # If specified: use exactly what's listed
    # If not specified: use defaults
```

**Recommendation**: **Option C (Hybrid)**
- Backwards compatible (missing config = defaults)
- Explicit when configured
- Clear intent either way

---

## Implementation Complexity

### Configuration Parsing

```go
// New config structure
type ToolDefinition struct {
    Type   string `json:"type"`   // "read", "write"
    Name   string `json:"name"`   // Static tool name
    Regexp string `json:"regexp"` // Dynamic pattern
    Prefix string `json:"prefix"` // Dynamic prefix
    Mode   string `json:"mode"`   // "insert", "update"
}

type ServerConfig struct {
    Tools []ToolDefinition `json:"tools" yaml:"tools"`
}

// Processing logic
func RegisterTools(srv AltinityMCPServer, cfg config.Config) {
    if len(cfg.Server.Tools) == 0 {
        // Use defaults
        registerDefaultTools(srv, cfg)
        return
    }
    
    // Process explicit config
    for _, toolDef := range cfg.Server.Tools {
        if toolDef.Name != "" && toolDef.Regexp == "" {
            // Static tool
            registerStaticTool(srv, toolDef)
        } else if toolDef.Regexp != "" {
            // Dynamic tool
            addDynamicToolRule(cfg, toolDef)
        } else {
            log.Error().Msg("Tool definition must have either name (static) or regexp (dynamic)")
        }
    }
    
    // Discover dynamic tools
    srv.EnsureDynamicTools(ctx)
}
```

**Code lines**: ~50-80  
**Complexity**: Medium (unified processing)  
**Maintainability**: High (less special casing)

---

## Final Verdict

| Aspect | Winner | Why |
|--------|--------|-----|
| **Clarity** | Unified | All tools in one place |
| **Simplicity** | Flag-based | Less config |
| **Flexibility** | Unified | Can customize everything |
| **Code quality** | Unified | Less special casing |
| **Backwards compat** | Flag-based | Easier transition |
| **Future-proofing** | Unified | Extensible design |

---

## Recommendation: UNIFIED CONFIG ✅

**This is better because:**

1. **Config-as-code**: Everything configurable, nothing hardcoded
2. **Self-documenting**: YAML file shows exact tool setup
3. **No magic**: No special flags or hidden logic
4. **Extensible**: Easy to add custom static tools later
5. **DevOps-friendly**: Infrastructure-as-code style
6. **Less code**: Unified processing logic
7. **Explicit**: See exactly what's registered

**With migration path:**
- Phase 1: Support both old (flag) and new (unified) config
- Phase 2: Deprecate old config with warnings
- Phase 3: Remove old config (v2.0 maybe)

---

## Proposed Final Config Structure

```yaml
server:
  tools:
    # Static tools (explicit)
    - type: "read"
      name: "execute_query"
    
    - type: "write"
      name: "write_query"
    
    # Dynamic tools (pattern-based)
    - type: "read"
      regexp: "analytics\\..*_view"
      prefix: "get_"
    
    - type: "write"
      regexp: "events\\..*_table"
      prefix: "log_"
      mode: "insert"
    
    - type: "write"
      regexp: "users\\..*_table"
      prefix: "create_"
      mode: "insert"

logging:
  level: "info"
```

**Clean, explicit, extensible** ✅

---

## Implementation Priority

1. **Phase 1** (Now): Config structure, backwards compat layer
2. **Phase 2** (Next): Move to unified config, deprecate old
3. **Phase 3** (Future): Remove old config support

Would you like to update the implementation plan to use unified config?
