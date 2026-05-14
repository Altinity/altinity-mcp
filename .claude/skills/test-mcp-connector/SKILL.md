---
name: test-mcp-connector
description: >
  Register a temporary MCP connector in claude.ai and/or chatgpt.com, verify it works,
  then offer cleanup. Trigger when the user wants to test an MCP server URL through a
  real AI frontend — phrases like "test mcp", "add test connector", "smoke-test mcp
  server", "register connector for testing", "check mcp in claude", "check mcp in chatgpt".
---

# Skill: test-mcp-connector

Automates end-to-end smoke-testing of an MCP server through the claude.ai and/or
chatgpt.com web frontends using the `chrome-devtools` MCP tools. Registers a
short-lived connector with a random suffix, verifies tool invocation succeeds, and
offers a cleanup flow.

---

## Phase 0 — Gather inputs

**If URL, base name, and target are already provided in the invocation prompt, skip
directly to Phase 1.**

Otherwise use `AskUserQuestion` to collect (in a single prompt):

1. **MCP server URL** — the remote MCP endpoint to register (required)
2. **Base name** — short identifier, e.g. `myserver` (required); the actual connector
   name will be `{basename}-{suffix}`
3. **Target** — where to register: `claude.ai only` / `chatgpt.com only` / `both`
   (default: both)

---

## Phase 1 — Generate connector name

```bash
openssl rand -hex 3   # produces 6 hex chars, e.g. a3f9c1
```

Connector name → `{basename}-{suffix}` (e.g. `myserver-a3f9c1`)

**Announce the full connector name to the user** before touching any browser tab.

---

## Phase 2 — Register on claude.ai

*(Skip if target is chatgpt.com only)*

1. `list_pages` — find a claude.ai tab; if none, `new_page` → `https://claude.ai/new`
2. `navigate_page` → `https://claude.ai/customize/connectors`
3. `take_snapshot` — verify page loaded
4. Click **Add connector** (expandable menu) → **Add custom connector**
   - **If disabled (Free plan, slot taken):** inform the user they must first remove
     the existing custom connector, wait for confirmation, then retry from step 4.
5. In the dialog, fill:
   - **Name** field → connector name
   - **Remote MCP server URL** field → URL
6. Click **Add**
7. If redirected to an Auth0/Google login page:
   - Click **Continue with Google**
   - On the Google account-chooser, select the personal account already signed in
   - Wait for redirect back to claude.ai
8. `take_snapshot` — confirm the connector appears in the sidebar and its tools are
   listed under Tool permissions

---

## Phase 3 — Register on chatgpt.com

*(Skip if target is claude.ai only)*

1. `list_pages` — find a chatgpt.com tab; if none, `new_page` → `https://chatgpt.com/`
2. `navigate_page` → `https://chatgpt.com/#settings/Connectors` (opens the Apps panel)
3. `take_snapshot`
4. Click **Advanced settings**
5. `take_snapshot` — check if **Developer mode** switch is `checked`
   - If not checked: click the switch to enable it; a **Create app** button will appear
6. Click **Create app**
7. In the "New App" dialog fill:
   - **Name** → connector name
   - **MCP Server URL** → URL
   - Leave **Authentication** as `OAuth` (default)
   - Check the **I understand and want to continue** checkbox
8. Click **Create** (becomes active once checkbox is checked)
9. If redirected to Auth0/Google:
   - Click **Continue with Google**
   - Select the personal Google account on the account-chooser page
   - Wait for OAuth callback; chatgpt.com will redirect back and show a
     "… is now connected" toast
10. `take_snapshot` — confirm connector appears under Enabled apps or Drafts with
    DEV badge

---

## Phase 4 — Verify

For each registered frontend:

1. `navigate_page` → new chat
   - claude.ai: `https://claude.ai/new`
   - chatgpt.com: `https://chatgpt.com/`
2. Click the chat input and type: `check {connector-name} mcp` → press Enter
3. Wait for the response to finish (poll with `take_screenshot` until the stop button
   disappears)
4. `take_screenshot` — capture the final response
5. Pass criteria: the response mentions the connector is connected **and** shows at
   least one successful tool call (whoami, execute_query, or any listed tool)

Report pass / fail per frontend with the screenshot evidence.

---

## Phase 5 — Cleanup

**If invoked autonomously (inputs were pre-provided in the prompt), skip the offer
and run Phase 6 immediately, then return the structured result from Phase 7.**

Otherwise present the user with:

- **Clean up now** → run Phase 6 immediately
- **Keep for now** → print a reminder block:

  ```
  Connector name : {connector-name}
  URL            : {url}
  Registered on  : {list of frontends}

  To remove later, run /test-mcp-connector cleanup
  or follow the manual steps in the skill's Phase 6.
  ```

If the user invokes the skill again with the word **cleanup** (e.g.
`/test-mcp-connector cleanup`), skip Phases 0-5 and go straight to Phase 6, asking
which connector name to remove.

---

## Phase 6 — Cleanup

### claude.ai

1. `navigate_page` → `https://claude.ai/customize/connectors`
2. `take_snapshot` — find the connector button by name
3. Click it → click **More options for {name}** (⋯ button) → **Remove**
4. Confirm in the dialog → **Remove**
5. `take_snapshot` — verify the connector is no longer listed

### chatgpt.com

1. `navigate_page` → `https://chatgpt.com/#settings/Connectors`
2. `take_snapshot` — find the connector in Enabled apps or Drafts
3. Click it → click the **⋯** menu → **Delete**
4. `take_snapshot` — verify neither Enabled apps nor Drafts list the connector

Report: "Cleanup complete — {name} removed from {frontends}."

---

## Phase 7 — Return result (autonomous mode only)

After cleanup, return a single structured paragraph:

```
PASS  {connector-name} — auth: <user-email> — tools invoked: whoami, execute_query — DB accessible. Connector removed.

FAIL  {connector-name} — {phase} failed: {reason}. Connector {removed|left in place}.
```

---

## Edge cases

| Situation | Handling |
|-----------|----------|
| claude.ai Free plan slot taken (interactive) | Prompt user to remove existing connector first |
| claude.ai Free plan slot taken (autonomous) | If existing connector matches `{basename}-*`, auto-remove it and continue; otherwise return FAIL immediately |
| chatgpt.com Developer mode off | Enable it before clicking Create app |
| Auth0 / Google OAuth during creation | Auto-click Continue with Google; pick personal account |
| Connector name already exists | Regenerate suffix and retry (rare with 6-char hex) |
| Chrome not running | Instruct user to run `iso chrome`; do not try to launch it |
| `take_snapshot` shows busy/loading | Poll with additional `take_snapshot` calls before acting |
