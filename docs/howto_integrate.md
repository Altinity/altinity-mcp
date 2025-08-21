# How to Integrate Altinity MCP with AI Tools

This guide provides step-by-step instructions for integrating the Altinity MCP Server with various AI tools and platforms.

## Table of Contents

- [Install Helm Chart with Minikube and Helm from GHCR.io (Token Enabled)](#install-helm-chart-with-minikube-and-helm-from-ghcrio-token-enabled)
- [Generate Token from JWE Token Generator](#generate-token-from-jwe-token-generator)
- [Integrate with Claude.ai Chat Web Interface](#integrate-with-claudeai-chat-web-interface)
- [Integrate with OpenAI ChatGPT GPTs](#integrate-with-openai-chatgpt-gpts)
- [Integrate with Claude Desktop](#integrate-with-claude-desktop)
- [Integrate with Claude Code (Claude MCP)](#integrate-with-claude-code-claude-mcp)
- [Integrate with Cursor.com](#integrate-with-cursorcom)
- [Integrate with Windsurf](#integrate-with-windsurf)

## Install Helm Chart with Minikube and Helm from GHCR.io (Token Enabled)

To install the Altinity MCP Helm chart with token authentication enabled using Minikube:

1. First, ensure you have Minikube and Helm installed:
   ```bash
   minikube start
   helm version
   ```

2. Install the Altinity MCP Helm chart from GHCR.io with token authentication enabled:
   ```bash
   helm install altinity-mcp oci://ghcr.io/altinity/altinity-mcp/helm/altinity-mcp \
     --set config.server.jwe.enabled=true \
     --set config.server.jwe.jweSecretKey="your-jwe-secret-key" \
     --set config.server.jwe.jwtSecretKey="your-jwt-secret-key" \
     --set config.server.transport=http \
     --set config.server.port=8080
   ```

3. Forward the port to access the service:
   ```bash
   kubectl port-forward service/altinity-mcp 8080:8080
   ```

For detailed configuration options, see the [Helm Chart README](../helm/altinity-mcp/README.md).

## Generate Token from JWE Token Generator

To generate a JWE token for authentication using Docker:

```bash
docker run --rm ghcr.io/altinity/altinity-mcp:latest jwe-token-generator \
  --jwe-secret-key "your-jwe-secret-key" \
  --jwt-secret-key "your-jwt-secret-key" \
  --host "clickhouse.example.com" \
  --port 8123 \
  --database "analytics" \
  --username "user123" \
  --password "password123" \
  --expiry 86400
```

This will output a JWE token that can be used for authentication with the Altinity MCP server.

## Integrate with Claude.ai Chat Web Interface

To integrate Altinity MCP with Claude.ai:

1.  Navigate to [https://claude.ai](https://claude.ai) and log in to your account.
2.  Go to **Settings** > **Connectors**.
    ![Claude Web Integration Step 1](screenshots/claude_web_connectors_0.jpg)
3.  In the **Connectors** settings, click on **Add custom connector**.
    ![Claude Web Integration Step 2](screenshots/claude_web_connectors_1.jpg)
4.  Enter a name for your connector (e.g., `altinity-mcp-jwe`) and the server URL, which should include the JWE token. For example: `https://host/token/http`.
    ![Claude Web Integration Step 3](screenshots/claude_web_connectors_2.jpg)
5.  After adding the connector, you can enable it for your chat session by clicking the tool icon.
    ![Claude Web Integration Step 4](screenshots/claude_web_connectors_3.jpg)
6.  You can see the list of available tools and enable or disable them.
    ![Claude Web Integration Step 5](screenshots/claude_web_connectors_4.jpg)
7.  Once enabled, you can use the tools in your chat. For example, you can ask Claude to list tables from your ClickHouse database.
    ![Claude Web Integration Step 6](screenshots/claude_web_connectors_5.jpg)
8.  Claude will show the results from the tool execution.
    ![Claude Web Integration Step 7](screenshots/claude_web_connectors_6.jpg)
9.  You can continue the conversation with Claude to analyze the data.
    ![Claude Web Integration Step 8](screenshots/claude_web_connectors_7.jpg)

## Integrate with OpenAI ChatGPT GPTs

To integrate Altinity MCP with OpenAI GPTs:

1.  Navigate to [https://chatgpt.com](https://chatgpt.com) and log in to your account.
2.  Go to the **GPTs** section and click **Create**.
    ![OpenAI GPTs Integration Step 1](screenshots/openai_gpts_1.jpg)
3.  In the configuration interface, go to the **Configure** tab.
    ![OpenAI GPTs Integration Step 2](screenshots/openai_gpts_2.jpg)
4.  Scroll down to the **Actions** section and click **Create new action**.
    ![OpenAI GPTs Integration Step 3](screenshots/openai_gpts_3.jpg)
5.  Import the OpenAPI schema from your Altinity MCP server URL. For example: `https://host/token/http`.
    ![OpenAI GPTs Integration Step 4](screenshots/openai_gpts_4.jpg)
6.  Configure the authentication with your JWE token using the **API Key** option.
    ![OpenAI GPTs Integration Step 5](screenshots/openai_gpts_5.jpg)
7.  Test the connection in the preview mode to ensure it's working properly.
    ![OpenAI GPTs Integration Step 6](screenshots/openai_gpts_6.jpg)
8.  You can now interact with your ClickHouse database using the GPT.
    ![OpenAI GPTs Integration Step 7](screenshots/openai_gpts_7.jpg)

## Integrate with Claude Desktop

To integrate Altinity MCP with Claude Desktop:

1.  Open the Claude Desktop application.
2.  Go to **Settings** > **Developer**.
    ![Claude Desktop Integration Step 1](screenshots/claude_desktop_local_mcp_1.jpg)
3.  In the **Local MCP servers** section, click on **Edit Config**.
4.  Add your Altinity MCP server details to the configuration file.
    ![Claude Desktop Integration Step 2](screenshots/claude_desktop_local_mcp_2.jpg)
5.  Save the configuration and restart the application to apply the changes.

## Integrate with Claude Code (Claude MCP)

To integrate Altinity MCP with Claude Code, you can use the `claude mcp add` command for HTTP transport:

```bash
claude mcp add altinity-mcp https://your-mcp-server-url/token/http
```

Replace `https://your-mcp-server-url/token/http` with the actual URL of your Altinity MCP server, including the JWE token.

This command will configure Claude Code to use your Altinity MCP server as a tool provider.

## Integrate with Cursor.com

To integrate Altinity MCP with Cursor.com, you need to add a new entry to the `mcpServers` section in the IDE's settings. This will allow you to use the Altinity MCP server as a tool provider.

```json
{
  "mcpServers": [
    {
      "name": "altinity-mcp",
      "type": "remote",
      "url": "https://your-mcp-server-url",
      "authorization": "Bearer your-jwe-token"
    }
  ]
}
```

Make sure to replace `https://your-mcp-server-url` with the correct URL for your Altinity MCP server and `your-jwe-token` with your actual JWE token.

## Integrate with Windsurf

To integrate Altinity MCP with Windsurf, you need to add a new entry to the `mcpServers` section in the IDE's settings. This will allow you to use the Altinity MCP server as a tool provider.

```json
{
  "mcpServers": [
    {
      "name": "altinity-mcp",
      "type": "remote",
      "url": "https://your-mcp-server-url",
      "authorization": "Bearer your-jwe-token"
    }
  ]
}
```

Make sure to replace `https://your-mcp-server-url` with the correct URL for your Altinity MCP server and `your-jwe-token` with your actual JWE token.

## Troubleshooting

If you encounter issues during integration:

1. Verify your Altinity MCP server is running and accessible
2. Ensure your JWE token is valid and not expired
3. Check that the server configuration matches the integration settings
4. Confirm network connectivity between the AI tool and your Altinity MCP server
5. Review server logs for authentication or connection errors

For more detailed troubleshooting, refer to the main [README.md](../README.md) file.
