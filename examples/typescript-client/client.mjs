// Independent MCP SDK client with an explicit JWT-SVID authentication adapter.
// A trusted local helper supplies a fresh SVID over stdin. No token is printed.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

let input = '';
for await (const chunk of process.stdin) input += chunk;
let resource, issuer, assertion, scope, allowLocalDemo;
const fetchJson = async (url, options = {}) => {
  const parsed = new URL(url);
  if (!allowLocalDemo || parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1') {
    throw new Error('unsafe scheme or demo host');
  }
  const response = await fetch(url, { ...options, redirect: 'error' });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
};
let client;
try {
  ({ resource, issuer, assertion, scope, allowLocalDemo = false } = JSON.parse(input));
  const target = new URL(resource);
  target.pathname = '/.well-known/oauth-protected-resource' + target.pathname;
  const prm = await fetchJson(target);
  if (prm.resource !== resource || !prm.authorization_servers.includes(issuer)) throw new Error('untrusted issuer');
  const metadata = new URL(issuer);
  metadata.pathname = '/.well-known/oauth-authorization-server' + metadata.pathname.replace(/\/$/, '');
  const meta = await fetchJson(metadata);
  if (meta.issuer !== issuer || !meta.token_endpoint_auth_methods_supported.includes('spiffe_jwt')) {
    throw new Error('unsupported authentication profile');
  }
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-spiffe',
    client_assertion: assertion, resource, scope,
  });
  const token = await fetchJson(meta.token_endpoint, { method: 'POST', body });
  client = new Client({ name: 'independent-svid-demo', version: '0.1.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(resource), {
    requestInit: { headers: { Authorization: `Bearer ${token.access_token}` }, redirect: 'error' },
  }));
  const tools = await client.listTools();
  const result = await client.callTool({ name: 'notes.search', arguments: { query: 'welcome' } });
  if (result.isError || !result.content.some(block => block.type === 'text' && block.text.includes('welcome'))) {
    throw new Error('unexpected tool result');
  }
  const names = tools.tools.map(tool => tool.name);
  if (scope === 'notes:read' && names.includes('notes.write')) throw new Error('tool visibility mismatch');
  let writeDenied = false;
  try {
    await client.callTool({ name: 'notes.write', arguments: { text: 'must be denied' } });
  } catch (error) {
    writeDenied = error.code === 403;
  }
  if (!writeDenied) throw new Error('write was not denied by scope');
  console.log(JSON.stringify({ event: 'interop', passed: true, tools: names, read: true, writeDenied }));
} catch {
  console.log(JSON.stringify({ event: 'interop', passed: false }));
  process.exitCode = 1;
} finally {
  if (client) await client.close();
}
