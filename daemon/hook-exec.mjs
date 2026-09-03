#!/usr/bin/env node
// Invoked BY the coding agent as a hook: `node hook-exec.mjs <EventName>`.
//
// Tether reports what an agent is doing so the web UI can mirror it. Every event except
// PermissionRequest is fire-and-forget: post the payload, exit, emit nothing. A hook that
// prints nothing is a hook with no opinion, so the agent behaves exactly as if Tether were
// not installed. PreToolUse in particular only OBSERVES — holding it would suppress prompts
// the CLI was about to raise and invent gates for calls it would have approved.
//
// PermissionRequest is the one event we hold. It fires only after the CLI has already
// decided a human must answer, so the agent is stopped either way; we just add a second
// place to answer from. That is the only channel that reaches a session with no terminal.
//
// It fails silent in every direction: daemon down, socket missing, timeout, malformed reply,
// no decision -> exit 0 with no output, and the CLI shows its own prompt as usual.
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';

const SOCK = process.platform === 'win32'
  ? '\\\\.\\pipe\\tether-hook'   // windows named pipe; same http API
  : path.join(os.homedir(), '.tether', 'hook.sock');
const event = process.argv[2] || 'Unknown';
const isGate = event === 'PermissionRequest';
// Ceiling only. The daemon answers the moment it decides not to hold, when a person
// answers, or when its own deadline lapses — all sooner. This stops a wedged socket from
// ever hanging a turn.
const CAP = isGate ? 900_000 : 1500;

let finished = false;
const done = () => { if (!finished) { finished = true; process.exit(0); } };
setTimeout(done, CAP).unref?.();

let body = '';
process.stdin.on('data', (c) => { body += c; });
process.stdin.on('end', () => {
  const req = http.request(
    { socketPath: SOCK, path: `/hook/${event}`, method: 'POST',
      headers: { 'content-type': 'application/json' }, timeout: CAP },
    (res) => {
      if (!isGate) { res.resume(); return res.on('end', done); } // drain and leave
      let out = '';
      res.on('data', (c) => { out += c; });
      res.on('end', () => {
        try {
          const { decision, decidedBy } = JSON.parse(out || '{}');
          // Anything but an explicit allow/deny stays silent and the CLI prompts as usual.
          // A timeout must never become "allow": that would override the user's own rules.
          //
          // The shape is the CLI's own rule, quoted from its validation error:
          //   PermissionRequest decision must be {"behavior":"allow"} or
          //   {"behavior":"deny","message":"..."}
          // `decision` is an OBJECT. A bare string is silently ignored and the local prompt
          // simply stays up — which is exactly what happened before this was fixed.
          if (decision === 'allow' || decision === 'deny') {
            const by = decidedBy ? ` by ${decidedBy}` : '';
            process.stdout.write(JSON.stringify({
              hookSpecificOutput: {
                hookEventName: 'PermissionRequest',
                decision: decision === 'allow'
                  ? { behavior: 'allow' }
                  : { behavior: 'deny', message: `Denied in Tether${by}` },
              },
            }));
          }
        } catch {}
        done();
      });
    },
  );
  req.on('timeout', () => { req.destroy(); done(); });
  req.on('error', done);                    // daemon down -> as if Tether were not installed
  req.end(body, isGate ? undefined : done); // non-gate events leave once it is on the wire
});
process.stdin.on('error', done);
