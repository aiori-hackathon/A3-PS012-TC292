"""Build deliverables/terminal-replay.html from captured asciinema casts.

Reads the three recorded casts (demo, verify-rate, kill switch), compresses
long silent gaps so playback is watchable, and embeds them into a single
static page with a dependency-free terminal-replay player.

Usage: uv run python tools/build_terminal_replay.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAST_FILES = [
    ROOT / "deliverables" / "casts" / "demo.cast",
    ROOT / "deliverables" / "casts" / "rate.cast",
    ROOT / "deliverables" / "casts" / "kill.cast",
]
OUT = ROOT / "deliverables" / "terminal-replay.html"

# Cap any silent gap at this duration so captures that finish with a long
# tool wait (e.g. the tcpdump capture window) still read as a live session.
MAX_GAP = 1.2

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>A3-PS012-TC292. Recorded terminal replay</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         background:#0b0d11; color:#e8ebf0; }
  main { max-width: 880px; margin: 0 auto; padding: 48px 20px 56px; }
  h1 { font-size: 1.35rem; letter-spacing: -0.02em; line-height: 1.25; margin: 0 0 6px; }
  .sub { color:#98a1b0; margin: 0 0 24px; font-size:.93rem; max-width: 68ch; }
  .sub code { background:#12151b; border:1px solid #232936; border-radius:5px; padding:1px 6px; }
  .segs { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; }
  .seg { border:1px solid #232936; background:#0e1117; color:#c8cdd6; padding:7px 14px;
         border-radius:999px; cursor:pointer; font-size:.88rem; transition: border-color .15s, color .15s; }
  .seg:hover { border-color:#3a4252; color:#e8ebf0; }
  .seg[aria-selected="true"] { background:#16283e; color:#9dc4f0; border-color:#2c4a73; }
  .screen { border:1px solid #232936; border-radius:10px; overflow:hidden; background:#000; }
  pre { margin:0; padding:16px 18px; font: 13px/1.5 ui-monospace,"SF Mono",Menlo,Consolas,monospace;
        color:#dbe2ea; white-space:pre-wrap; word-break:break-word; max-height:60vh; overflow-y:auto; }
  .bar { display:flex; align-items:center; gap:12px; padding:10px 14px; background:#0e1117;
         border-top:1px solid #232936; }
  button { border:1px solid #2a303c; background:#161a22; color:#e8ebf0; border-radius:6px;
           padding:7px 0; cursor:pointer; font-size:.9rem; min-width:56px;
           transition: background .15s; }
  button:hover { background:#1d2330; }
  button:active { transform: translateY(1px); }
  button:focus-visible, input:focus-visible, .seg:focus-visible { outline:2px solid #7fb4e8; outline-offset:1px; }
  input[type=range] { flex:1; accent-color:#4f8fdd; }
  .meta { font-size:.8rem; color:#98a1b0; white-space:nowrap; font-family:ui-monospace,Menlo,monospace; }
  .note { color:#98a1b0; font-size:.85rem; margin-top:18px; line-height:1.65; }
  .note strong { color:#c8cdd6; }
  .note code { background:#12151b; border:1px solid #232936; border-radius:4px; padding:1px 5px; }
</style>
</head>
<body>
<main>
  <h1>Recorded terminal replay</h1>
  <p class="sub">Recordings of the real runs, with silent gaps compressed.
  Play, scrub the bar, switch 1x / 2x / 4x, space toggles. To re-run it yourself:
  install the two manual prerequisites (Docker and <code>uv</code>, see the README),
  then <code>make demo</code>.</p>
  <div class="segs" id="tabs" role="tablist"></div>
  <div class="screen">
    <pre id="term"></pre>
    <div class="bar">
      <button id="play" aria-label="Play or pause">&#9654;</button>
      <input type="range" id="seek" min="0" max="1000" value="0" aria-label="Seek">
      <button id="speed" aria-label="Playback speed">1x</button>
      <span class="meta" id="meta"></span>
    </div>
  </div>
  <p class="note">
    <strong>Replay 1</strong>: <code>make demo</code>, the one-command demo: canary
    self-check, lab up, scan of 20 authorised targets, compare, <strong>20/20
    accuracy</strong>, reports written.<br>
    <strong>Replay 2</strong>: <code>make verify-rate</code>: captured traffic peaks
    at <strong>1 qps per target (cap 1)</strong> and 5 qps global (cap 5); 30 DNS
    questions including one self-check control query.<br>
    <strong>Replay 3</strong>: kill switch: <code>touch /app/KILL</code> mid-scan,
    then "kill switch triggered; stopping cleanly" at 13 targets, exit 0.<br>
    Source: the committed <code>*.cast</code> files next to this page. Rebuild with
    <code>uv run python tools/build_terminal_replay.py</code>.
  </p>
</main>
<script id="casts" type="application/json">__CASTS__</script>
<script>
const casts = JSON.parse(document.getElementById('casts').textContent);
const termPre = document.getElementById('term');
const playBtn = document.getElementById('play');
const speedBtn = document.getElementById('speed');
const seekEl = document.getElementById('seek');
const metaEl = document.getElementById('meta');

let cur = 0, ev = [], t = 0, idx = 0, speedMult = 1, raf = null, last = 0;

class Term {
  constructor(el) { this.el = el; this.lines = ['']; this.row = 0; this.col = 0; this.ansi = false; }
  put(text) {
    for (const ch of text) {
      if (this.ansi) { if (ch >= '@' && ch <= '~') this.ansi = false; continue; }
      if (ch === '\\x1b') { this.ansi = true; continue; }
      if (ch === '\\r') { this.col = 0; continue; }
      if (ch === '\\n') { this.row++; this.col = 0; if (this.row >= this.lines.length) this.lines.push(''); continue; }
      const line = this.lines[this.row];
      if (this.col < line.length) {
        this.lines[this.row] = line.slice(0, this.col) + ch + line.slice(this.col + 1);
      } else {
        this.lines[this.row] = line + ' '.repeat(this.col - line.length) + ch;
      }
      this.col++;
    }
    this.render();
  }
  render() {
    this.el.textContent = this.lines.slice(0, this.row + 1).join('\\n');
    this.el.scrollTop = this.el.scrollHeight;
  }
}

let term = new Term(termPre);

function titleHeader(c) {
  return c.title + '\\n' + '='.repeat(Math.min(78, c.width)) + '\\n\\n';
}

function selectCast(i) {
  stopPlayback(); cur = i;
  document.querySelectorAll('.seg').forEach((b, j) => b.setAttribute('aria-selected', j === i ? 'true' : 'false'));
  ev = casts[i].events.map(e => e.slice());
  t = 0; idx = 0; seekEl.value = 0;
  term = new Term(termPre);
  term.put(titleHeader(casts[i]));
  updateMeta();
}

function updateMeta() {
  const c = casts[cur];
  metaEl.textContent = Math.min(t, c.duration).toFixed(1) + 's / ' + c.duration + 's';
}

function tick(now) {
  t += (now - last) / 1000 * speedMult; last = now;
  while (idx < ev.length && ev[idx][0] <= t) { term.put(ev[idx][1]); idx++; }
  if (seekEl !== document.activeElement) seekEl.value = Math.min(1000, Math.round(t / casts[cur].duration * 1000));
  updateMeta();
  if (idx >= ev.length) { stopPlayback(); playBtn.innerHTML = '&#8634;'; return; }
  raf = requestAnimationFrame(tick);
}

function startPlayback() {
  if (idx >= ev.length) { selectCast(cur); }
  playBtn.innerHTML = '&#10073;&#10073;';   // pause glyph
  last = performance.now();
  raf = requestAnimationFrame(tick);
}

function stopPlayback() {
  playBtn.innerHTML = '&#9654;';
  if (raf) cancelAnimationFrame(raf);
  raf = null;
}

playBtn.addEventListener('click', () => (raf ? stopPlayback() : startPlayback()));

seekEl.addEventListener('input', () => {
  stopPlayback();
  const frac = seekEl.value / 1000;
  t = frac * casts[cur].duration;
  idx = ev.findIndex(e => e[0] >= t); if (idx < 0) idx = ev.length;
  term = new Term(termPre);
  term.put(titleHeader(casts[cur]));
  for (let i = 0; i < idx; i++) term.put(ev[i][1]);
  updateMeta();
});

speedBtn.addEventListener('click', () => {
  speedMult = speedMult === 1 ? 2 : speedMult === 2 ? 4 : 1;
  speedBtn.textContent = speedMult + 'x';
});

document.addEventListener('keydown', e => {
  if (e.target.tagName !== 'INPUT' && e.code === 'Space') {
    e.preventDefault(); (raf ? stopPlayback() : startPlayback());
  }
});

const tabsEl = document.getElementById('tabs');
casts.forEach((c, i) => {
  const b = document.createElement('button');
  b.className = 'seg';
  b.type = 'button';
  b.setAttribute('role', 'tab');
  b.setAttribute('aria-selected', i === 0 ? 'true' : 'false');
  b.textContent = (i + 1) + '. ' + c.title.replace(/^A3-PS012:\\s*/, '').replace(/\\s+-.*/, '') + ' (' + c.duration + 's)';
  b.addEventListener('click', () => selectCast(i));
  tabsEl.appendChild(b);
});
selectCast(0);
updateMeta();
</script>
</body>
</html>
"""

def compress_cast(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    events: list[list] = []
    prev_t = 0.0
    for line in lines[1:]:
        t, etype, data = json.loads(line)
        if etype != "o":
            continue
        gap = t - prev_t
        if events and gap > MAX_GAP:
            gap = MAX_GAP
        prev_t = t
        events.append([round((events[-1][0] if events else 0.0) + gap, 4), data])
    if events:
        events[0][0] = 0.0
    title = header.get("title", path.stem).replace("\u2014", "-")  # em-dash out
    return {
        "title": title,
        "width": header.get("width", 80),
        "height": header.get("height", 24),
        "duration": round(events[-1][0], 2) if events else 0,
        "events": events,
    }


def main() -> None:
    casts = [compress_cast(p) for p in CAST_FILES if p.exists()]
    if len(casts) != len(CAST_FILES):
        missing = [p.name for p in CAST_FILES if not p.exists()]
        raise SystemExit(f"missing casts: {missing}")
    page = PAGE_TEMPLATE.replace("__CASTS__", json.dumps(casts))
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")
    for c in casts:
        print(f"  {c['duration']:>6.1f}s  {len(c['events']):>4} events  {c['title'][:60]}")


if __name__ == "__main__":
    main()
