// Watches session roots for *.jsonl changes; tails incrementally by byte offset.
// Backfill on first sight is capped (plan §3.1) so a 56MB session doesn't flood the relay.
import fs from 'node:fs';
import path from 'node:path';

const BACKFILL_CAP = 2 * 1024 * 1024; // bytes of history per session on first sight
const DEBOUNCE_MS = 60;

export class Tailer {
  /**
   * @param {string[]} roots directories to watch recursively
   * @param {(file: string, lines: string[]) => void} onLines
   * @param {(file: string) => void} onTruncate file shrank; caller should reset the session
   * @param {Record<string, number>} offsets persisted byte offsets (mutated in place)
   */
  constructor(roots, onLines, onTruncate, offsets, log = () => {}) {
    this.roots = roots;
    this.onLines = onLines;
    this.onTruncate = onTruncate;
    this.offsets = offsets;
    this.log = log;
    this.remainders = new Map();
    this.timers = new Map();
    this.watchers = [];
    this.maxInitialSessions = 100;
  }

  start() {
    for (const root of this.roots) {
      if (!fs.existsSync(root)) { this.log(`watch root missing: ${root}`); continue; }
      this.initialScan(root);
      const w = fs.watch(root, { recursive: true }, (_ev, fname) => {
        if (!fname || !fname.endsWith('.jsonl')) return;
        this.schedule(path.join(root, fname));
      });
      w.on('error', (e) => this.log(`watcher error on ${root}: ${e.message}`));
      this.watchers.push(w);
      this.log(`watching ${root}`);
    }
  }

  stop() { for (const w of this.watchers) w.close(); for (const t of this.timers.values()) clearTimeout(t); }

  initialScan(root) {
    const files = [];
    const walk = (dir) => {
      let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith('.jsonl')) {
          try { files.push({ p, mtime: fs.statSync(p).mtimeMs }); } catch {}
        }
      }
    };
    walk(root);
    files.sort((a, b) => b.mtime - a.mtime);
    for (const f of files.slice(0, this.maxInitialSessions)) this.tail(f.p);
  }

  schedule(file) {
    if (this.timers.has(file)) return;
    this.timers.set(file, setTimeout(() => { this.timers.delete(file); this.tail(file); }, DEBOUNCE_MS));
  }

  tail(file) {
    let st; try { st = fs.statSync(file); } catch { return; } // deleted
    let offset = this.offsets[file];
    if (offset === undefined) {
      // first sight: cap backfill, align to a line start
      offset = 0;
      if (st.size > BACKFILL_CAP) {
        offset = this.alignToLine(file, st.size - BACKFILL_CAP);
        this.log(`backfill capped for ${path.basename(file)} (skipping ${offset} bytes)`);
      }
    } else if (st.size < offset) {
      this.log(`file shrank, resetting: ${path.basename(file)}`);
      this.remainders.delete(file);
      this.offsets[file] = 0;
      this.onTruncate(file);
      offset = st.size > BACKFILL_CAP ? this.alignToLine(file, st.size - BACKFILL_CAP) : 0;
    }
    if (st.size === offset) { this.offsets[file] = offset; return; }

    let fd;
    try {
      fd = fs.openSync(file, 'r');
      const len = st.size - offset;
      const buf = Buffer.alloc(Math.min(len, 8 * 1024 * 1024));
      let read = 0, pos = offset;
      while (pos < st.size) {
        const n = fs.readSync(fd, buf, 0, Math.min(buf.length, st.size - pos), pos);
        if (n <= 0) break;
        pos += n;
        const chunk = buf.subarray(0, n).toString('utf8');
        const prev = this.remainders.get(file) ?? '';
        const data = prev + chunk;
        const parts = data.split('\n');
        const rem = parts.pop() ?? '';
        this.remainders.set(file, rem);
        const lines = parts.filter((l) => l.trim().length > 0);
        if (lines.length) this.onLines(file, lines);
        read += n;
      }
      this.offsets[file] = pos;
    } catch (e) {
      this.log(`tail error ${file}: ${e.message}`);
    } finally {
      if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    }
  }

  // re-tail a file from scratch (after a session reset)
  retail(file) { delete this.offsets[file]; this.remainders.delete(file); this.schedule(file); }

  alignToLine(file, approxOffset) {
    // advance to the byte after the next newline so we start on a whole line
    let fd;
    try {
      fd = fs.openSync(file, 'r');
      const buf = Buffer.alloc(64 * 1024);
      let pos = approxOffset;
      for (;;) {
        const n = fs.readSync(fd, buf, 0, buf.length, pos);
        if (n <= 0) return pos;
        const idx = buf.subarray(0, n).indexOf(0x0a);
        if (idx >= 0) return pos + idx + 1;
        pos += n;
      }
    } catch { return approxOffset; }
    finally { if (fd !== undefined) try { fs.closeSync(fd); } catch {} }
  }
}
