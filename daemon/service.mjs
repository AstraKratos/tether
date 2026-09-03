// Keeping tetherd running in the background, per operating system.
//
// Tether itself is portable — it is only the "run this at login and restart it if it
// dies" part that differs. Each platform gets its own implementation behind one
// interface so the rest of the daemon never branches on process.platform.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const LABEL = 'ai.tether.tetherd';
const run = (cmd, args) => {
  try { return { ok: true, out: execFileSync(cmd, args, { timeout: 15000 }).toString().trim() }; }
  catch (e) { return { ok: false, out: (e.stderr?.toString() || e.message).trim() }; }
};

// ---------------------------------------------------------------- macOS (launchd)
const launchd = {
  name: 'launchd',
  file: () => path.join(os.homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`),
  write(nodeBin, script, logPath) {
    const p = this.file();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array>
    <string>${nodeBin}</string><string>${script}</string><string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${logPath}</string>
  <key>StandardErrorPath</key><string>${logPath}</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:${os.homedir()}/.local/bin:/usr/bin:/bin</string>
  </dict>
</dict></plist>\n`);
    return p;
  },
  start() {
    const target = `gui/${process.getuid()}`;
    run('launchctl', ['bootout', `${target}/${LABEL}`]); // clear any previous copy
    try { execFileSync('sleep', ['2']); } catch {}
    let r = run('launchctl', ['bootstrap', target, this.file()]);
    if (!r.ok) { try { execFileSync('sleep', ['3']); } catch {} r = run('launchctl', ['bootstrap', target, this.file()]); }
    return r;
  },
  stop() { return run('launchctl', ['bootout', `gui/${process.getuid()}/${LABEL}`]); },
  remove() { try { fs.unlinkSync(this.file()); return true; } catch { return false; } },
};

// ---------------------------------------------------------------- Linux (systemd --user)
const systemd = {
  name: 'systemd (user)',
  file: () => path.join(os.homedir(), '.config', 'systemd', 'user', 'tetherd.service'),
  write(nodeBin, script) {
    const p = this.file();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, `[Unit]
Description=Tether daemon — mirrors local AI coding sessions
After=network-online.target

[Service]
Type=simple
ExecStart=${nodeBin} ${script} run
Restart=always
RestartSec=3
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
`);
    return p;
  },
  start() {
    run('systemctl', ['--user', 'daemon-reload']);
    const r = run('systemctl', ['--user', 'enable', '--now', 'tetherd.service']);
    // so the daemon survives logout on servers; harmless if it fails
    run('loginctl', ['enable-linger', os.userInfo().username]);
    return r;
  },
  stop() { return run('systemctl', ['--user', 'disable', '--now', 'tetherd.service']); },
  remove() { try { fs.unlinkSync(this.file()); run('systemctl', ['--user', 'daemon-reload']); return true; } catch { return false; } },
};

// ---------------------------------------------------------------- Windows (Task Scheduler)
// schtasks ships with Windows, so this needs no extra install and no admin rights for a
// per-user logon task. A .cmd shim keeps the task definition readable and quoting sane.
const schtasks = {
  name: 'Task Scheduler',
  file: () => path.join(os.homedir(), '.tether', 'bin', 'tetherd-service.cmd'),
  write(nodeBin, script, logPath) {
    const p = this.file();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, `@echo off
"${nodeBin}" "${script}" run >> "${logPath}" 2>&1
`);
    return p;
  },
  start() {
    // /f overwrites a previous definition; onlogon starts it without a console window
    const r = run('schtasks', ['/create', '/f', '/tn', 'Tetherd', '/sc', 'onlogon', '/tr', `"${this.file()}"`]);
    if (!r.ok) return r;
    return run('schtasks', ['/run', '/tn', 'Tetherd']);
  },
  stop() {
    run('schtasks', ['/end', '/tn', 'Tetherd']);
    return run('schtasks', ['/delete', '/f', '/tn', 'Tetherd']);
  },
  remove() { try { fs.unlinkSync(this.file()); return true; } catch { return false; } },
};

// ------------------------------------------------- anything else: run it yourself
const manual = {
  name: 'manual',
  file: () => null,
  write() { return null; },
  start() { return { ok: false, out: 'no supported service manager on this platform' }; },
  stop() { return { ok: false, out: 'nothing to stop' }; },
  remove() { return false; },
};

export function serviceFor(platform = process.platform) {
  if (platform === 'darwin') return launchd;
  if (platform === 'linux') return systemd;
  if (platform === 'win32') return schtasks;
  return manual;
}

/** Cross-platform "is this command on PATH?" */
export function whichBin(bin, env = process.env) {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const out = execFileSync(finder, [bin], { env, timeout: 4000 }).toString().trim();
    return out.split(/\r?\n/)[0] || null;
  } catch { return null; }
}

/** Cross-platform "stop any stray daemon that is not under the service manager". */
export function killStrays() {
  if (process.platform === 'win32') return run('taskkill', ['/F', '/IM', 'node.exe', '/FI', 'WINDOWTITLE eq tetherd*']);
  return run('pkill', ['-f', 'tetherd.mjs run']);
}

/**
 * Can Tether reach a live agent TUI on this machine to answer its prompts?
 * Injecting keystrokes needs a terminal multiplexer we can address from outside the
 * session. tmux provides that on macOS and Linux. Windows has no equivalent we can drive
 * safely — SendKeys targets whichever window happens to be focused, which risks typing
 * into the wrong application, so we decline rather than guess.
 */
export function terminalBackend() {
  if (process.platform === 'win32') {
    return { kind: 'none', reason: 'live answering needs tmux, which Windows does not provide. Run your agents under WSL to enable it — mirroring and prompt display work either way.' };
  }
  return whichBin('tmux')
    ? { kind: 'tmux' }
    : { kind: 'none', reason: 'tmux is not installed. Install it to answer prompts remotely; mirroring works without it.' };
}
