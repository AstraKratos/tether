#!/usr/bin/env node
// An MCP server that lets any agent pull another agent's chat into its own context.
//
// Installed into Claude Code, Cursor and Codex by `tetherd mcp install`. The case it exists for
// is the one Tether cannot drive from outside: an IDE chat panel. In Cursor you just ask "load my
// last Claude Code session for this project" and the agent calls get_session_context itself.
//
// Reads transcripts straight from disk (the same files tetherd tails); the daemon does not need
// to be running. Speaks JSON-RPC 2.0 over stdio, newline-delimited, no dependencies.
import path from 'node:path';
import readline from 'node:readline';
import { AGENT_NAMES, listSessions, resolveSession, buildHandoff, writeHandoff, recordHandoff } from './handoff.mjs';

const PROTOCOL = '2024-11-05';
const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
const ok = (id, result) => send({ jsonrpc: '2.0', id, result });
const text = (t, isError = false) => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError: true } : {}) });
const ago = (ms) => {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  return s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`;
};

const TOOLS = [
  {
    name: 'list_sessions',
    description: 'List recent AI coding chat sessions on this machine (Claude Code and Cursor), newest first, '
      + 'so one can be continued here. Pass cwd to see only sessions for one project folder.',
    inputSchema: {
      type: 'object',
      properties: {
        cwd: { type: 'string', description: 'Absolute project folder to filter by (usually the current workspace).' },
        agent: { type: 'string', enum: ['claude', 'cursor'], description: 'Only sessions from this agent.' },
        limit: { type: 'number', description: 'How many to return (default 15, max 100).' },
      },
    },
  },
  {
    name: 'get_session_context',
    description: 'Load the full working context of another AI coding session — its goal, every request the person made, '
      + 'files changed, commands run, current git state and the latest turns — so you can continue that work here. '
      + 'Use session_id "latest" with cwd for the most recent session in a project.',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string', description: 'A session id or unique prefix from list_sessions, or "latest".' },
        cwd: { type: 'string', description: 'Project folder, used with "latest" and as the place to write the file.' },
        note: { type: 'string', description: 'Optional note to include, e.g. what to do next.' },
        write_file: { type: 'boolean', description: 'Also save it to <project>/.tether/handoff/ (git-ignored). Default false.' },
      },
      required: ['session_id'],
    },
  },
];

function callTool(name, args = {}) {
  if (name === 'list_sessions') {
    const limit = Math.min(100, Math.max(1, Number(args.limit) || 15));
    const rows = listSessions({ cwd: args.cwd ? path.resolve(args.cwd) : null, agent: args.agent ?? null, limit });
    if (!rows.length) return text(args.cwd ? `No sessions found for ${args.cwd}.` : 'No sessions found on this machine.');
    return text(rows.map((s) => `${s.sessionId}  ${(AGENT_NAMES[s.agent] ?? s.agent).padEnd(11)}  ${ago(s.updatedAt).padEnd(8)}  `
      + `${s.title ?? '(untitled)'}${s.cwd ? `  — ${s.cwd}` : ''}`).join('\n')
      + '\n\nLoad one with get_session_context({ session_id }).');
  }
  if (name === 'get_session_context') {
    const cwdArg = args.cwd ? path.resolve(args.cwd) : null;
    const s = resolveSession(args.session_id, { cwd: cwdArg });
    const cwd = s.cwd ?? cwdArg;
    const h = buildHandoff({ file: s.file, agent: s.agent, sessionId: s.sessionId, cwd, title: s.title, note: args.note ?? null,
      // without a file on disk, point at the original transcript for anything not summarized
      transcriptRef: args.write_file ? null : s.file });
    let md = h.markdown;
    if (args.write_file) {
      const w = writeHandoff(h, cwd);
      recordHandoff({ id: h.id, from: { sessionId: s.sessionId, agent: s.agent, title: s.title }, to: { agent: 'mcp' }, cwd, path: w.path, mode: 'mcp' });
      md += `\n\n(Saved to ${w.path}.)`;
    }
    return text(md);
  }
  throw new Error(`unknown tool: ${name}`);
}

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const { id, method } = msg;
  if (id === undefined || id === null) return; // notifications need no answer
  if (method === 'initialize') {
    return ok(id, { protocolVersion: PROTOCOL, capabilities: { tools: {} }, serverInfo: { name: 'tether-sessions', version: '1' } });
  }
  if (method === 'tools/list') return ok(id, { tools: TOOLS });
  if (method === 'tools/call') {
    try { return ok(id, callTool(msg.params?.name, msg.params?.arguments ?? {})); }
    catch (e) { return ok(id, text(`Tether: ${e.message}`, true)); }
  }
  if (method === 'ping') return ok(id, {});
  return send({ jsonrpc: '2.0', id, error: { code: -32601, message: `unsupported method: ${method}` } });
});
