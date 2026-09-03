// Executes remote intents. Deliberately narrow (plan §6): it can resume/continue a
// Claude session, start a new one with a chosen agent CLI, and nothing else. Each agent
// is invoked through a fixed argument template — never a shell, never arbitrary commands.
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { terminalBackend } from './service.mjs';
import os from 'node:os';
import path from 'node:path';



// how each supported agent CLI takes a one-shot prompt in a folder
const AGENT_ARGS = {
  claude: (t) => ['-p', t],
  codex: (t) => ['exec', t],
  opencode: (t) => ['run', t],
  cursor: (t) => ['-p', t],
  gemini: (t) => ['-p', t],
  aider: (t) => ['--message', t],
};
const AGENT_BIN = { claude: 'claude', codex: 'codex', opencode: 'opencode', cursor: 'cursor-agent', gemini: 'gemini', aider: 'aider' };

// per-agent runtime options from the web UI, whitelisted here before touching argv
const MODEL_RE = /^[A-Za-z0-9 ._\/:@,-]{1,100}$/;
const CLAUDE_MODES = new Set(['acceptEdits', 'plan', 'bypassPermissions']);
const CODEX_SANDBOX = new Set(['read-only', 'workspace-write']);

export class Executor {
  constructor(claudeBin, log = () => {}) {
    this.claudeBin = claudeBin;
    this.log = log;
  }

  /**
   * @param {object} job { promptId, text, sessionId?, cwd, agent?, opts? }
   * @param {(status: string, detail?: string) => void} report
   */
  run(job, report) {
    const o = job.opts ?? {};
    const model = MODEL_RE.test(o.model ?? '') ? o.model : null;
    // A new session can be started as a real INTERACTIVE agent inside tmux instead of a
    // one-shot headless run. That is what makes it answerable from anywhere later: the
    // TUI stays alive, so permission prompts can be mirrored and answered remotely.
    if (!job.sessionId && job.interactive) {
      return this.runInteractive(job, report, { model, mode: o.mode });
    }
    let bin, args;
    if (job.sessionId) { // resuming an existing (Claude) session
      bin = this.claudeBin;
      args = ['--resume', job.sessionId];
      if (model) args.push('--model', model);
      if (CLAUDE_MODES.has(o.mode)) args.push('--permission-mode', o.mode);
      args.push('-p', job.text);
    } else {
      const agent = AGENT_ARGS[job.agent] ? job.agent : 'claude';
      bin = agent === 'claude' ? this.claudeBin : AGENT_BIN[agent];
      args = AGENT_ARGS[agent](job.text);
      if (agent === 'claude') {
        if (model) args.push('--model', model);
        if (CLAUDE_MODES.has(o.mode)) args.push('--permission-mode', o.mode);
      } else if (agent === 'codex') {
        if (o.sandbox === 'full-auto') args.splice(1, 0, '--full-auto');
        else if (CODEX_SANDBOX.has(o.sandbox)) args.splice(1, 0, '--sandbox', o.sandbox);
        if (model) args.splice(1, 0, '-m', model);
      } else if (model) {
        args.push(agent === 'aider' ? '--model' : '-m', model);
      }
    }
    this.log(`exec: ${bin} ${args.map((a) => (a.length > 40 ? a.slice(0, 40) + '…' : a)).join(' ')} (cwd ${job.cwd})`);
    report('executing');
    let child;
    try {
      child = spawn(bin, args, {
        cwd: job.cwd,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, PATH: `${process.env.PATH ?? ''}:/usr/local/bin:/opt/homebrew/bin` },
      });
    } catch (e) {
      return report('failed', `spawn error: ${e.message}`);
    }
    let errTail = '';
    child.stderr.on('data', (c) => { errTail = (errTail + c.toString()).slice(-2000); });
    child.stdout.resume(); // transcript file is the mirror; stdout is drained and dropped
    child.on('error', (e) => report('failed', `spawn error: ${e.message}`));
    child.on('close', (code) => {
      if (code === 0) report('done');
      else report('failed', `${bin} exited ${code}: ${errTail.trim().slice(-500)}`);
    });
  }

  /** Start an interactive agent in a tmux window, then type the first prompt into it. */
  runInteractive(job, report, { model, mode }) {
    const env = { ...process.env, PATH: `${process.env.PATH ?? ''}:/usr/local/bin:/opt/homebrew/bin` };
    const tmux = (args) => execFileSync('tmux', args, { timeout: 8000, maxBuffer: 2_000_000, env }).toString();
    const term = terminalBackend();
    if (term.kind !== 'tmux') return report('failed', `cannot start an interactive session: ${term.reason}`);
    const agent = AGENT_ARGS[job.agent] ? job.agent : 'claude';
    const bin = agent === 'claude' ? this.claudeBin : AGENT_BIN[agent];
    const argv = [bin];
    if (agent === 'claude') {
      if (model) argv.push('--model', model);
      if (CLAUDE_MODES.has(mode)) argv.push('--permission-mode', mode);
    }
    const name = `tether-${String(job.promptId).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 12)}`;
    report('executing');
    try {
      tmux(['new-session', '-d', '-s', name, '-c', job.cwd, argv.join(' ')]);
    } catch (e) {
      return report('failed', `could not start tmux session: ${e.message}`);
    }
    // Wait for the TUI to be ready before typing, otherwise the prompt is swallowed.
    const started = Date.now();
    const tick = () => {
      let pane = '';
      try { pane = tmux(['capture-pane', '-t', name, '-p']); }
      catch { return report('failed', 'the interactive session exited before it was ready'); }
      // The agent asks its own "do you trust this folder?" question. Tether does NOT answer
      // it — answering a security prompt on the user's behalf would be exactly the kind of
      // interference Tether must never do. The session stays open so it can be answered in
      // the web UI (it is mirrored like any other prompt) or on the machine itself.
      if (/trust this folder|trust the files|Do you trust|Quick safety check/i.test(pane)) {
        this.log(`interactive session for ${job.cwd} is waiting on its own trust prompt (tmux "${name}")`);
        return report('done', `started in tmux "${name}", waiting on the agent's trust prompt — answer it to continue`);
      }
      const ready = /\u276f\s*$|shortcuts|for agents/i.test(pane.replace(/\s+$/, ''));
      if (ready) {
        try {
          for (const line of String(job.text).replace(/\r/g, '').split('\n').entries()) {
            const [i, l] = line;
            if (i) tmux(['send-keys', '-t', name, 'M-Enter']);
            if (l) tmux(['send-keys', '-t', name, '-l', l]);
          }
          tmux(['send-keys', '-t', name, 'Enter']);
        } catch (e) { return report('failed', `could not send the first prompt: ${e.message}`); }
        this.log(`interactive session started in tmux "${name}" (cwd ${job.cwd})`);
        return report('done', `started in tmux session "${name}" — attach with: tmux attach -t ${name}`);
      }
      if (Date.now() - started > 60_000) return report('failed', 'the interactive session did not become ready in 60s');
      setTimeout(tick, 1500);
    };
    setTimeout(tick, 2500);
  }
}
