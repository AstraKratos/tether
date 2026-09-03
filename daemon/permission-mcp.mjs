#!/usr/bin/env node
// A one-tool MCP server, passed to `claude -p` as --permission-prompt-tool.
//
// This is the ONLY channel that reaches a session with no terminal: an IDE-hosted or
// headless run has no TTY and no tmux pane, so keystroke injection cannot answer it.
//
// It also cannot disturb auto mode, by construction. Claude Code evaluates permissions in
// order — hooks, deny rules, ask rules, permission MODE, allow rules, then the prompt tool —
// so anything auto mode approves is resolved two steps earlier and never arrives here. We
// are called only for the calls the CLI genuinely could not decide on its own.
//
// Speaks JSON-RPC 2.0 over stdio (newline-delimited), no dependencies. Every call is
// forwarded to tetherd over the unix socket, which mirrors it to the web UI and waits.
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import readline from 'node:readline';

const SOCK = path.join(os.homedir(), '.tether', 'hook.sock');
const SESSION_ID = process.env.TETHER_SESSION_ID || null;
const TOOL_NAME = 'permission_prompt';
const PROTOCOL = '2024-11-05';

const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
const ok = (id, result) => send({ jsonrpc: '2.0', id, result });

// Ask tetherd for a decision. Resolves to the permission result the CLI expects, or null
// when Tether cannot answer (daemon down, nobody watching) so the caller can fall back.
function askDaemon(payload) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ ...payload, session_id: SESSION_ID });
    const req = http.request(
      { socketPath: SOCK, path: '/permission', method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
      (res) => {
        let out = '';
        res.on('data', (c) => { out += c; });
        res.on('end', () => { try { resolve(JSON.parse(out || 'null')); } catch { resolve(null); } });
      },
    );
    req.on('error', () => resolve(null)); // daemon down -> fall through to the default below
    req.end(body);
  });
}

// The CLI reads the tool's text content as JSON:
//   allow -> { behavior: "allow", updatedInput }   (updatedInput is required)
//   deny  -> { behavior: "deny",  message }
// For AskUserQuestion the answer travels inside updatedInput as { questions, answers }.
async function decide(input) {
  const toolName = input?.tool_name ?? '?';
  const toolInput = input?.input ?? {};
  const answer = await askDaemon({ tool_name: toolName, input: toolInput, tool_use_id: input?.tool_use_id ?? null });

  if (answer?.behavior === 'allow') {
    return { behavior: 'allow', updatedInput: answer.updatedInput ?? toolInput };
  }
  if (answer?.behavior === 'deny') {
    return { behavior: 'deny', message: answer.message || 'Denied from the Tether web UI' };
  }
  // No answer at all. Denying is the only safe default: this session has no human at a
  // terminal, so "allow" would auto-approve exactly the calls the CLI wanted checked.
  return {
    behavior: 'deny',
    message: 'Nobody answered this request in Tether, so it was not approved. '
      + 'Open the Tether web UI to approve it, or run this task where you can answer locally.',
  };
}

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', async (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const { id, method } = msg;
  if (id === undefined || id === null) return; // a notification; nothing to answer

  if (method === 'initialize') {
    return ok(id, {
      protocolVersion: PROTOCOL,
      capabilities: { tools: {} },
      serverInfo: { name: 'tether', version: '1' },
    });
  }
  if (method === 'tools/list') {
    return ok(id, {
      tools: [{
        name: TOOL_NAME,
        description: 'Ask the person running Tether whether this tool call may proceed.',
        inputSchema: {
          type: 'object',
          properties: {
            tool_name: { type: 'string', description: 'The tool awaiting a decision' },
            input: { type: 'object', description: 'The arguments that tool was called with' },
            tool_use_id: { type: 'string', description: 'Identifier of the pending call' },
          },
          required: ['tool_name', 'input'],
        },
      }],
    });
  }
  if (method === 'tools/call') {
    if (msg.params?.name !== TOOL_NAME) {
      return send({ jsonrpc: '2.0', id, error: { code: -32601, message: `unknown tool: ${msg.params?.name}` } });
    }
    let result;
    try { result = await decide(msg.params?.arguments ?? {}); }
    catch (e) { result = { behavior: 'deny', message: `Tether could not get a decision: ${e.message}` }; }
    return ok(id, { content: [{ type: 'text', text: JSON.stringify(result) }] });
  }
  if (method === 'ping') return ok(id, {});
  return send({ jsonrpc: '2.0', id, error: { code: -32601, message: `unsupported method: ${method}` } });
});
