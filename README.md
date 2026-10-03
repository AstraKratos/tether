# Tether 📡

Mirror your local AI coding sessions — **Claude Code**, **Cursor**, **Codex** — to a web app you
can open from your phone, get notified the moment one needs you, and answer its questions from
anywhere.

Tether **never changes what an agent does.** Every agent's own permission logic runs exactly as
if Tether were not installed, and Tether never invents a prompt the agent would not have raised.
What it adds is a second place to answer: when an agent genuinely stops to ask you something — a
permission, a question, a plan to approve — that prompt appears in the web UI *and* in your
terminal at the same time, and whichever you answer first wins.

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

The relay serves the landing page at `/` — what Tether is, how it works, how to connect, with
a sign-in link into the app — so anyone you point at your relay lands on something that
explains itself. **The app is at `/app`** (`/welcome` is an alias for the landing page). A
relay running without `site/` serves the app at `/` as before.

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

Tether has ordinary email + password sign-in, and stays end-to-end encrypted while doing it.
The trick is that your password never reaches the relay: the browser derives two values from
it, an *auth hash* (sent, to prove who you are) and a *wrap key* (kept, never sent). The wrap
key seals your account encryption key into a blob the relay stores but cannot open. Signing in
downloads that blob and unwraps it locally.

- **Sign up** — *Create account* with an email and password. Account id and encryption key are
  generated in the browser; the relay is handed the auth hash and the sealed key, nothing else.
- **Sign in** — same email and password on any browser or phone. Each sign-in mints its own
  client token, so signing in somewhere new never signs you out anywhere else.
- **Log out** — clears that one browser and calls nothing on the relay. **Paired machines keep
  running and stay connected**: daemons authenticate with their own Ed25519 device keys, which
  have nothing to do with browser sessions. Sign back in whenever you like.
- **Link a device** (optional) — a one-time `TETHERC.…` code, for signing in another browser
  without typing the password, or for accounts created before email login existed. The relay
  only ever sees a hash of the code; codes expire in 10 minutes.

Each email is a separate account. Devices, sessions and events are scoped to an account id on
every read and write, so two accounts on one relay never see each other's machines.

The one irrecoverable case: an account with **no** email login, logged out of every browser.
Then only a link code from a still-signed-in device can get back in. Set an email login from
*Link a device* if you are in that position.

## Remote approvals

Install the hooks where you want approval gating (per project, or globally):

```bash
node daemon/tetherd.mjs hooks install --settings <project>/.claude/settings.json   # one project
node daemon/tetherd.mjs hooks install --settings ~/.claude/settings.json          # everywhere
```

Two mechanisms, chosen by how the session was started. Neither ever holds a call the agent
would have approved on its own.

**Interactive sessions** (a terminal, Cursor, VS Code — anything you started yourself) use the
`PermissionRequest` hook. It fires only *after* Claude Code has decided a human must answer, so
the agent is already stopped waiting; Tether holds that hook, puts a card in the web UI, and
returns your decision. The local prompt stays on screen the whole time — answer at the machine
or on your phone, first wins. No matcher: every tool that prompts is covered, MCP tools included.
If nobody answers within `approvalTimeoutSec` (default 600s) the hook returns nothing and the
local prompt simply remains. `PreToolUse` only observes, to give the mirror context.

**Runs Tether starts itself** (a prompt or new session sent from the web UI) are headless and
have no terminal to prompt at, so they get `--permission-prompt-tool` pointing at Tether's own
MCP server. Claude Code calls it only for decisions it could not make itself — auto mode, allow
rules and deny rules are all evaluated first — and the answer comes back from the web UI. For
`AskUserQuestion` the card shows the actual choices and your pick is returned as the answer.

`Stop` / `Notification` hooks make state changes (finished / needs input) instant; sessions
without hooks fall back to a 90s inactivity timer.

**What cannot be answered remotely:** the folder-trust dialog, login and OAuth prompts, sandbox
network prompts and managed-settings approval. No hook fires for these — they happen outside any
tool call — so they are shown in the UI but must be answered at the machine. Set
`remoteApprovals: false` in `~/.tether/config.json` to turn remote approvals off entirely.

## Continue a chat in another agent (handoff)

When Claude Code hits its plan limit, pick the same work up in Cursor or Codex, or the other way
round, with the context intact. No agent can resume another's native session, so Tether writes
what a person taking over would need to `<project>/.tether/handoff/<id>.md` (git-ignored):

- the original request and every later request, word for word;
- Claude Code's own compaction summary, when there is one;
- the plan and to-dos, the files changed and the commands run;
- the current git status and uncommitted diff;
- the latest turns, verbatim.

A searchable copy of the whole conversation sits next to it. The new agent starts with a
one-line prompt that points at the file. No model writes the summary: the agent that just hit
its limit can't be the one to write it.

- **Web UI:** open a session → **Continue in…** → pick the agent and how it should run
  (interactive in tmux, a headless run, or just write the file and paste one line into an IDE
  chat). When a session stops on a plan limit, a banner offers the same thing. The new session
  links back to the one it continues, and the other way round.
- **CLI:** `tetherd sessions` lists chats for the current folder (`--all` for every folder).
  `tetherd handoff <id|latest> --to cursor` starts the target in your terminal with the context
  loaded. Other flags: `--headless`, `--file-only`, `--note "…"`, `--model`, `--mode`.
- **From inside any agent:** `tetherd mcp install` (also run by `tetherd connect`) adds a
  `tether-sessions` MCP server to Claude Code, Cursor and Codex. It has two tools, `list_sessions`
  and `get_session_context`, so in Cursor's chat you can just ask *"load my latest Claude Code
  session for this project"*.

Claude Code and Cursor chats can be the source. Codex keeps its sessions in SQLite, so it can
be a target but not a source yet. Devin runs in the cloud and can't see local uncommitted work;
it needs its own adapter.

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

`deploy/` has a systemd unit and a Caddyfile (automatic Let's Encrypt) for a Linux box. On
macOS, `tetherd relay-service install` does the same job through launchd.

### Running a relay other people use

A relay open to the internet holds other people's data on a finite disk, so four limits apply.
All are environment variables, and all can be turned off for a private relay:

| Variable | Default | What it does |
|---|---|---|
| `TETHER_RETAIN_DAYS` | `30` | Events older than this are deleted hourly, along with sessions left empty and settled approvals/prompts. `0` keeps everything forever. |
| `TETHER_MAX_SESSION_EVENTS` | `50000` | Per-session cap, oldest trimmed first, so one runaway session can't fill the disk ahead of the sweep. |
| `TETHER_REG_PER_IP_PER_DAY` | `5` | New accounts allowed per IP per day. Reads `X-Forwarded-For`, so put it behind a proxy that sets it. |
| `TETHER_INVITE_CODE` | unset | When set, registration requires this code. Unset means anyone can sign up. |

The relay prints its policy on startup, so you can see what a deployment is actually enforcing.

**Retention only limits how far back the web UI can scroll.** The transcripts themselves live in
`~/.claude/projects` on each user's own machine and are never touched — nobody loses their
history, only remote access to the older part of it. Daemons are told the window on connect so
they don't re-upload sessions the relay has already swept.

Two operational notes. Deleting rows leaves free pages that SQLite reuses, so the file stops
growing but does not shrink; if you migrate an existing relay and want the space back, run
`sqlite3 $TETHER_DB VACUUM` once. And back the database up — it holds every account, device
pairing and stored event:

```bash
sqlite3 "$TETHER_DB" ".backup /var/backups/tether-$(date +%F).sqlite"
```

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
