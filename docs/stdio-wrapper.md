# stdio wrapper

`mcp-svid-stdio` starts a local stdio MCP server with a short-lived access token instead of a static key in its environment.

## Usage

```sh
mcp-svid-stdio --resource URI --scope SCOPE --trusted-issuer URL [options] -- command [args...]
```

Example, as an MCP host config entry:

```json
{
  "command": "mcp-svid-stdio",
  "args": [
    "--resource", "http://notes-a:8101/mcp", "--scope", "notes:read",
    "--trusted-issuer", "http://authz:8100",
    "--allow-http", "--allow-private-network", "--", "my-stdio-server"
  ]
}
```

`--allow-http` and `--allow-private-network` are needed only because this example uses compose service names over plain http. Without them the wrapper accepts only `https` URLs that resolve to public addresses, and refuses anything else with a `url_refused` event on stderr and exit code 2.

The child must read the token from `MCP_ACCESS_TOKEN_FILE` before each upstream call.

## Behaviour

1. Fetches an access token for `--resource` with the wrapper's own JWT-SVID (same flow as the agent, see [Architecture](architecture.md#token-flow)).
2. Writes it to `token` in a private temp dir (`mcp-svid-*`), mode 0600, replaced atomically.
3. Starts the child with `MCP_ACCESS_TOKEN_FILE` set to that path. Any inherited `MCP_ACCESS_TOKEN` is removed.
4. stdin and stdout are inherited, so the MCP stdio stream flows directly between host and child.
5. Rewrites the file `--refresh-margin` seconds (default 60) before expiry. Inside the margin it retries every 0.5 to 5 seconds.
6. Forwards SIGINT and SIGTERM to the child.
7. On exit, deletes the token file and the temp dir.

## Fail closed

If refresh keeps failing until the token expires, the wrapper:

1. Deletes the token file.
2. Terminates the child.
3. Exits with code 75 (`EX_TEMPFAIL`).

If the first token fetch fails, the child is never started. Otherwise the wrapper exits with the child's exit code.

## `--export-token-env`

Also sets `MCP_ACCESS_TOKEN` to the first token. A process environment cannot be changed from outside, so the child lives at most one token lifetime: when the exported token expires, the wrapper terminates the child and exits with code 75. The MCP host then starts it again, and the new child gets a fresh token. The token file is still written and refreshed in this mode.

| Property | Token file (default) | `--export-token-env` |
|---|---|---|
| Visible to | Owner UID via file mode 0600 | Same UID via the process environment |
| Inherited by grandchildren | Only the path | The value |
| Refreshed | Yes | No. The child is stopped at the token expiry instead |
| Child lifetime | Until it exits or refresh fails | At most one token lifetime (300s) |

Grandchildren that detach from the child are not stopped and keep the expired value. Use this mode only for children that cannot read a file.

## Status

Minimal. Children must re-read `MCP_ACCESS_TOKEN_FILE` per upstream call.
