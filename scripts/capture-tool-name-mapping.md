# Capturing the tool-name mapping

How a tool name travels from an upstream MCP server, through the Omnodex MCP
proxy, to the name an agent makes callable and reports in its hook payloads.

None of this is documented by the agent vendors, and it is not stable across
versions, so it is measured rather than assumed. The results live in
`packages/hooks-provider/test/fixtures/tool-name-mapping.json` and are asserted
by `packages/hooks-provider/test/tool-name-mapping.test.mjs`. Re-run this when
a platform releases a major version, or when a correlation bug suggests the
mapping has moved.

The mapping matters because correlating a hook observation with a proxy
observation of the same call depends on the proxy's tool name still being
recognisable inside the agent's. If a platform started rewriting characters
instead of passing them through, that would break, and the fixture is how we
would find out.

## 1. Build and point a fixture upstream at the proxy

```bash
npx tsc -b

export CAPTURE_HOME="$(mktemp -d)"
cat > "$CAPTURE_HOME/omnodex-proxy.json" <<EOF
{
  "version": 1,
  "redact_parameters": false,
  "upstream_servers": [
    {
      "name": "demo",
      "transport": "stdio",
      "command": "node",
      "args": ["$PWD/packages/mcp-proxy/test/helpers/mock-mcp-server.mjs"],
      "env": {
        "MOCK_SERVER_NAME": "demo",
        "MOCK_TOOLS": "[\"read_file\",\"read-file\",\"read.file\",\"read/file\"]"
      }
    }
  ]
}
EOF
```

The four names cover the character classes worth testing: the underscore the
proxy itself joins on, the hyphen that agent tool-name patterns usually allow,
and the dot and slash that they usually do not.

## 2. What the proxy exposes

Confirm the proxy's own view first, so a missing tool later can be attributed
to the agent rather than to the proxy:

```bash
node - "$CAPTURE_HOME" <<'EOF'
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
const client = new Client({ name: "probe", version: "0" }, { capabilities: {} });
await client.connect(new StdioClientTransport({
  command: "node",
  args: ["packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js"],
  env: { ...process.env, OMNODEX_HOME: process.argv[2] },
  stderr: "ignore",
}));
await new Promise((r) => setTimeout(r, 2500));   // upstream discovery window
console.log((await client.listTools()).tools.map((t) => t.name));
await client.close();
process.exit(0);
EOF
```

Expect all four, prefixed and joined on `__`, characters untouched.

## 3. What the agent exposes

### Claude Code

```bash
cat > /tmp/omnodex-capture-mcp.json <<EOF
{ "mcpServers": { "omnodex": {
    "command": "node",
    "args": ["$PWD/packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js"],
    "env": { "OMNODEX_HOME": "$CAPTURE_HOME" } } } }
EOF

OMNODEX_HOME="$CAPTURE_HOME" claude -p \
  "List every tool you have whose name contains 'read'. Print the exact tool names verbatim, one per line, and nothing else. Do not call any of them." \
  --mcp-config /tmp/omnodex-capture-mcp.json --strict-mcp-config
```

Compare against step 2. A name that appears in step 2 and not here did not
survive the agent, and the fixture should record how.

To capture a routed call as well, add
`--allowedTools "mcp__omnodex__demo__read_file"` and ask for that tool to be
called. Note that hooks do **not** fire in headless `-p` mode, so the proxy
half lands in `$CAPTURE_HOME` but the hook half does not: take the hook half
from a real interactive session's event log instead.

### Codex

```bash
OMNODEX_HOME="$CAPTURE_HOME" codex exec \
  -c "mcp_servers.omnodex={command=\"node\", args=[\"$PWD/packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js\"], env={OMNODEX_HOME=\"$CAPTURE_HOME\"}}" \
  -c 'approval_policy="never"' \
  "Print the exact verbatim name of every tool available to you, one per line, including tools from MCP servers. Do not call any tool."
```

As of Codex CLI v0.155.0-alpha.9.2, `/mcp verbose` lists the proxy tools in an
interactive CLI session, but the CLI does not make local MCP tools callable by
the model. Capture the model-visible mapping in ChatGPT Desktop instead:

1. Register three temporary MCP servers that each launch the proxy with a
   separate `OMNODEX_HOME`: one exposing `read_file` plus `read-file`, one
   exposing `read.file`, and one exposing `read/file`.
2. Fully restart ChatGPT Desktop. Starting a new task without restarting the
   app does not refresh its MCP registry.
3. Inspect the callable tool names, then call each tool with a unique input so
   its Codex hook and proxy events can be paired without relying on the name.
4. Restore the previous MCP configuration and restart Desktop again.

The measured result is that Codex replaces hyphen, dot, and slash with
underscore. If two names then collide, both receive different 12-hex suffixes.
The MCP inventory retains the original names, but the model-callable and hook
names do not. See the fixture for the exact capture.

## 4. Record it

Update `tool-name-mapping.json` with the client version, the date, and what
each name became. The test asserts the mapping code agrees with the fixture, so
a change in observed behaviour shows up as a failing test rather than as
silently uncorrelated events.
