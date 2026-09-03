#!/usr/bin/env node
// Invoked BY the coding agent as a hook: `node hook-exec.mjs <EventName>`.
//
// Tether OBSERVES. It reports what an agent is doing so the web UI can mirror it, and it
// must never change how that agent behaves. So this process:
//   * emits NOTHING on stdout — a hook that prints nothing is a hook with no opinion, so
//     the agent's own permission logic runs exactly as if Tether were not installed;
//   * never waits on the daemon's answer — the payload is posted and we exit, so a slow
//     or wedged daemon cannot add latency to a tool call;
//   * always exits 0, even on error, so a broken Tether can never fail someone's turn.
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';

const SOCK = process.platform === 'win32'
  ? '\\\\.\\pipe\\tether-hook'   // windows named pipe; same http API
  : path.join(os.homedir(), '.tether', 'hook.sock');
const event = process.argv[2] || 'Unknown';
const HARD_CAP = 1500; // absolute ceiling; we normally exit far sooner

const done = () => process.exit(0);
const bail = setTimeout(done, HARD_CAP);
bail.unref?.();

let body = '';
process.stdin.on('data', (c) => { body += c; });
process.stdin.on('end', () => {
  const req = http.request(
    { socketPath: SOCK, path: `/hook/${event}`, method: 'POST', headers: { 'content-type': 'application/json' }, timeout: HARD_CAP },
    (res) => { res.resume(); res.on('end', done); }, // drain and leave; the reply is not used
  );
  req.on('timeout', () => { req.destroy(); done(); });
  req.on('error', done);   // daemon down -> behave as if Tether were not installed
  req.end(body, done);     // exit as soon as the payload is on the wire
});
process.stdin.on('error', done);
