# Tether 📡

Mirror your local AI coding sessions — **Claude Code**, **Cursor**, **Codex** — to a web app you
can open from your phone, get notified the moment one needs you, and answer its questions from
anywhere.

Tether **observes and relays; it never intervenes.** Its hooks emit nothing, so every agent's own
permission logic runs exactly as if Tether were not installed. It mirrors a question only when the
agent genuinely asks one.

Transcripts are **end-to-end encrypted**: the relay stores ciphertext and routing metadata only.
The account key lives in your browser and on paired machines; it travels only inside pairing
codes you copy yourself.

## Layout

- `daemon/` — `tetherd`, runs on each machine: tails each agent's transcripts, installs
  and removes their hooks, mirrors the questions they ask, and relays your answers back.
  Zero third-party dependencies.
- `daemon/agents.mjs` — per-agent integration (Claude Code, Codex, Cursor): where each keeps
  its hooks, the shape they take, and which transcripts are tailable.
- `daemon/service.mjs` — keeping it running per OS: launchd (macOS), systemd user unit
  (Linux), Task Scheduler (Windows).
- `relay/` — WebSocket gateway + SQLite store + serves the app. Deliberately blind.
- `app/` — the web client (vanilla ES modules, no build step).
- `test/client.mjs` — headless client speaking the same protocol; used for e2e tests.

## Quick start (single machine)

```bash
npm install                      # one dependency: ws
node relay/server.mjs            # relay on http://127.0.0.1:8787
# open http://127.0.0.1:8787 in a browser -> Create account -> "Pair a machine"
# run the printed command on the machine:
node daemon/tetherd.mjs pair 'TETHER1.…' --relay http://127.0.0.1:8787 --name my-mac
node daemon/tetherd.mjs run      # or: node daemon/tetherd.mjs launchd install
```

### Reaching it from a phone / tablet

WebSockets work from any browser on any device — the app connects to whatever origin served
it. Two deployment requirements:

1. The relay must be reachable: `HOST=0.0.0.0 PORT=8787 node relay/server.mjs` (LAN) or a
   proper deploy (small VM, Fly, Railway).
2. **HTTPS is required on anything that isn't localhost** — browsers only expose
   `crypto.subtle` (used for E2E decryption) on secure origins, and `wss://` comes with it.
   Quick test: `cloudflared tunnel --url http://127.0.0.1:8787`. Permanent: Caddy/nginx +
   Let's Encrypt, or Tailscale Serve for private-to-your-devices access.

Then pair daemons with `--relay https://<your-host>`.

## Accounts: sign up, log in, link devices

Tether is end-to-end encrypted, so there is no email/password login — the server never has
your key, so it cannot "log you in". Instead (like Signal/WhatsApp device linking):

- **Sign up** — first device: *Create account* generates the account id, encryption key and
  client token locally (browser localStorage).
- **Log in** — every other browser/phone: on a logged-in device press **Link a device**, move
  the one-time `TETHERC.…` code over a channel you trust, and paste it into **Log in** on the
  new device. The new device gets its own revocable client token; the relay only ever sees a
  hash of the code. Codes are one-time and expire in 10 minutes.
- **Log out** — forgets the account on that browser. The key is unrecoverable from the server
  by design, so keep at least one linked device (or a saved login code).

## Remote approvals

Install the hooks where you want approval gating (per project, or globally):

```bash
node daemon/tetherd.mjs hooks install --settings <project>/.claude/settings.json   # one project
node daemon/tetherd.mjs hooks install --settings ~/.claude/settings.json          # everywhere
```

`PreToolUse` (matcher `Bash|Write|Edit|NotebookEdit`) blocks up to 4 minutes waiting for a
remote decision; if none arrives, it answers nothing and the normal local permission flow
takes over. Tether can only ever *add* a way to answer, never lock you out. `Stop` /
`Notification` hooks make state changes (finished / needs input) instant; sessions without
hooks fall back to a 90s inactivity timer.

## Failure doctrine

Every mechanism degrades to exactly what happens without Tether: daemon down → sessions run
locally and the mirror catches up on reconnect (transcript files are the durable log);
relay down → daemon retries with backoff; hook timeout → local prompt.

## Security notes (v1)

- Relay DB holds ciphertext only (AES-256-GCM, per-scope keys via HKDF from the account secret).
- Daemons authenticate with Ed25519 device keys (challenge/response); clients with a bearer token.
- The daemon's remote surface is narrow by design: resume/spawn `claude`, answer its own hooks — no generic shell.
- Account secret sits in browser localStorage and `~/.tether/identity.json` (0600): fine for
  personal use behind TLS; multi-user hardening is future work (plan M6).

## Status

M0–M4 of the build plan implemented and verified locally (mirror, pairing+E2E, hook
notifications, remote approvals, remote prompting incl. new sessions). Not yet done:
Web Push to a locked phone (M2 leg), Codex adapter (M5), hardening (M6).


## Install

```bash
npm i -g @astrakratos/tetherd
tetherd connect <pairing-code> --relay https://your-relay
```

`connect` pairs the machine, installs hooks for every agent it finds, registers their transcript
directories, and starts the background service. `tetherd disconnect` reverses all of it and leaves
third-party hooks untouched.

## Self-hosting the relay

```bash
TETHER_DB=/var/lib/tether/relay.sqlite HOST=0.0.0.0 PORT=8787 tetherd relay
```

Put TLS in front of it — pairing codes carry your encryption key. Give `TETHER_DB` a persistent
volume; it is SQLite, so an ephemeral container loses everything on redeploy.

## Platform support

| | macOS | Linux | Windows |
|---|---|---|---|
| Mirror sessions | ✅ | ✅ | ✅ |
| Agent hooks | ✅ | ✅ | ✅ (named pipe) |
| Background service | launchd | systemd (user) | Task Scheduler |
| Answer prompts remotely | ✅ tmux | ✅ tmux | via WSL only |

Answering a live prompt means typing into a running TUI, which needs tmux. Windows has no
equivalent that can be driven safely from outside, so on Windows the question is still mirrored —
you just answer it on the machine (or run agents under WSL).


## Security notes for self-hosting

Two things to settle before putting a relay on the public internet:

**TLS is required.** The relay speaks plain HTTP and WebSocket, which is fine on `127.0.0.1`
but not in public: pairing codes carry your account encryption key. Terminate TLS in front of it
(Caddy, nginx, or your platform's proxy) and forward the WebSocket upgrade on `/ws`.

**Registration is open.** `POST /api/register` accepts anyone who can reach the relay, so a public
deployment lets strangers create accounts on your server. Put it behind a private network, an
invite check, or your proxy's auth if that isn't what you want. Login is rate-limited
(10 attempts / 15 min per email); registration is not.

Everything sensitive lives outside the repo, in `~/.tether/`:

| Path | Contents |
|---|---|
| `~/.tether/identity.json` | device keypair and account secret (mode 0600) |
| `~/.tether/relay.sqlite` | the relay store — ciphertext and routing metadata only |
| `~/.tether/state.json` | per-file read offsets, so restarts resume rather than replay |

## Configuration

All optional; nothing is needed to run locally.

| Variable | Default | Use |
|---|---|---|
| `TETHER_DB` | `~/.tether/relay.sqlite` | point at a persistent volume when hosting |
| `PORT` | `8787` | relay listen port |
| `HOST` | `127.0.0.1` | set `0.0.0.0` when the platform routes to the container directly |
