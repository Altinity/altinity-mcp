# Tool Safety Hints

Altinity MCP uses MCP tool annotations to describe how risky a tool is and whether it can affect resources outside a bounded target.

## Hints

- `readOnlyHint`
  Set to `true` for tools that only read, retrieve, or compute data and do not create, update, delete, or send data outside the client.

- `destructiveHint`
  Set to `true` for tools that can delete, overwrite, or otherwise have irreversible side effects.

- `openWorldHint`
  Set to `true` for tools that can write to arbitrary external resources such as URLs, files, or other unbounded targets. Set to `false` for bounded writes to known resources.

## Important Relationship

Per the OpenAI Apps SDK guidance, `destructiveHint` and `openWorldHint` are only relevant for write-capable tools, meaning when `readOnlyHint=false`.

## Official References

- OpenAI Apps SDK reference:
  [https://developers.openai.com/apps-sdk/reference](https://developers.openai.com/apps-sdk/reference)
- OpenAI Apps SDK MCP server guide:
  [https://developers.openai.com/apps-sdk/build/mcp-server](https://developers.openai.com/apps-sdk/build/mcp-server)
- Model Context Protocol schema for `ToolAnnotations`:
  [https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations)
