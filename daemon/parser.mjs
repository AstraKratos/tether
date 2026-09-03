// Claude Code JSONL -> normalized TranscriptEvents, preserving enough structure that
// the web app can render each event the way Claude Code itself does (plan §3.3, "ditto").
// Verified against Claude Code 2.1.222 shapes (2026-09-02).

// Internal bookkeeping Claude Code writes but never renders in the transcript.
const SKIP_TYPES = new Set([
  'queue-operation', 'file-history-snapshot', 'file-history-delta', 'atis-latch',
  'last-prompt', 'progress', 'frame-link', 'mode', 'permission-mode', 'pr-link',
  'artifact-autoreact-ledger', 'artifact-comment-monitor', 'attachment',
]);

const MAX_TEXT = 20000;         // per text/result blob
const MAX_IMAGE_B64 = 3_000_000; // ~2.2MB decoded; skip larger to keep events sane
const ANSI_RE = new RegExp('\\x1b\\[[0-9;?]*[A-Za-z]', 'g');

const cap = (s, n = MAX_TEXT) => (typeof s === 'string' && s.length > n ? s.slice(0, n) + `\n… [+${s.length - n} chars]` : s);

function blocksToText(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((b) => (typeof b === 'string' ? b : b?.type === 'text' ? (b.text ?? '') : '')).join('\n');
  return String(content);
}

// Returns { events:[...], meta:{...}|null, title:string|null }
export function normalizeLine(raw) {
  let o;
  try { o = JSON.parse(raw); } catch { return { events: [], meta: null, title: null }; }
  const out = { events: [], meta: null, title: null };
  const ts = o.timestamp ?? null;

  if (o.cwd || o.gitBranch || o.version || o.permissionMode) {
    out.meta = {};
    if (o.cwd) out.meta.cwd = o.cwd;
    if (o.gitBranch) out.meta.gitBranch = o.gitBranch;
    if (o.version) out.meta.version = o.version;
    // the permission mode the session is actually in right now, so the web UI can
    // mirror the local choice instead of guessing
    if (o.permissionMode) out.meta.permissionMode = o.permissionMode;
  }
  // Cursor writes {role, message:{content:[…]}} where Claude writes {type, message:{…}};
  // the block shapes match, so treating role as the type makes its chats mirror too.
  const kind = o.type ?? o.role ?? null;
  if (SKIP_TYPES.has(kind) || o.isSidechain || o.isMeta) return out;

  const uuid = o.uuid ?? null;
  const push = (ev) => out.events.push({ ts, uuid, ...ev });

  switch (kind) {
    case 'user': {
      const c = o.message?.content;
      if (typeof c === 'string') { if (c.trim()) push({ kind: 'text', role: 'user', text: cap(c) }); break; }
      if (Array.isArray(c)) {
        for (const b of c) {
          if (b?.type === 'text') { if (b.text?.trim()) push({ kind: 'text', role: 'user', text: cap(b.text) }); }
          else if (b?.type === 'tool_result') {
            const arr = Array.isArray(b.content) ? b.content : null;
            const imgs = arr ? arr.filter((x) => x?.type === 'image').map(imgUrl).filter(Boolean) : [];
            push({ kind: 'tool_result', toolUseId: b.tool_use_id ?? null, isError: !!b.is_error,
                   text: cap(blocksToText(b.content).replace(ANSI_RE, '')), images: imgs });
          } else if (b?.type === 'image') { const u = imgUrl(b); if (u) push({ kind: 'image', role: 'user', dataUrl: u }); }
        }
      }
      break;
    }
    case 'assistant': {
      const c = o.message?.content;
      const model = o.message?.model ?? null;
      // the model that actually served this turn is the ground truth for "what am I on now"
      if (model && model !== '<synthetic>') out.meta = { ...(out.meta ?? {}), model };
      if (Array.isArray(c)) {
        for (const b of c) {
          if (b?.type === 'text') { if (b.text?.trim()) push({ kind: 'text', role: 'assistant', text: cap(b.text), model }); }
          else if (b?.type === 'thinking') { if (b.thinking?.trim()) push({ kind: 'thinking', text: cap(b.thinking) }); }
          else if (b?.type === 'tool_use') push({ kind: 'tool_use', tool: b.name ?? '?', toolUseId: b.id ?? null, input: capInput(b.input ?? {}) });
        }
      } else if (typeof c === 'string' && c.trim()) push({ kind: 'text', role: 'assistant', text: cap(c), model });
      break;
    }
    case 'system': {
      const t = blocksToText(o.content ?? o.message ?? '').replace(ANSI_RE, '');
      if (t.trim()) push({ kind: 'system', text: cap(t) });
      break;
    }
    case 'ai-title': out.title = o.aiTitle ?? null; break;
    case 'custom-title': out.title = o.customTitle ?? o.title ?? null; break;
    case 'summary': out.title = o.summary ?? null; break;
    default:
      break; // unrecognized bookkeeping types are ignored, matching the CLI
  }
  return out;
}

function imgUrl(b) {
  const s = b?.source;
  if (s?.type === 'base64' && s.data && s.media_type) {
    if (s.data.length > MAX_IMAGE_B64) return `[image too large to mirror: ${(s.data.length / 1e6).toFixed(1)}MB]`;
    return `data:${s.media_type};base64,${s.data}`;
  }
  if (s?.type === 'url' && s.url) return s.url;
  return null;
}

// keep structured input, but cap long string fields (file contents, diffs) so events stay bounded
function capInput(input) {
  if (!input || typeof input !== 'object') return input;
  const out = {};
  for (const [k, v] of Object.entries(input)) out[k] = typeof v === 'string' ? cap(v, 12000) : v;
  return out;
}

export function splitLines(prevRemainder, chunk) {
  const data = prevRemainder + chunk;
  const lines = data.split('\n');
  const remainder = lines.pop() ?? '';
  return [lines.filter((l) => l.trim().length > 0), remainder];
}
