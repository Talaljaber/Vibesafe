import type {
  AttackOutcome,
  AttackResult,
  AttackRun,
  ProbeGroup,
  RetestDiff,
  RetestState,
} from "../types.js";

const SAFE_KEY_RE = /^[\w.-]{1,64}$/;
const LOOPBACK_RE = /^http:\/\/(?:127\.0\.0\.1|\[::1\]|localhost)(?::\d+)?(?:\/|$)/;

function esc(value: unknown): string {
  return String(value)
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeKey(key: string): string {
  return SAFE_KEY_RE.test(key) ? key : "<key>";
}

/** Defensive second redaction pass for HTML excerpts (emails, JWTs, key-like strings). */
function redactExcerpt(text: string): string {
  return text
    .replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, "[email]")
    .replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]*/g, "[jwt]")
    .replace(/\b(?:sb_(?:secret|publishable)_|sk[-_]|pk[-_]|ghp_|AKIA)[\w-]{6,}/g, "[key]")
    .replace(/\b[A-Za-z0-9_-]{32,}\b/g, "[token]")
    .slice(0, 200);
}

const OUTCOME_LABEL: Record<AttackOutcome, string> = {
  CONFIRMED: "Live confirmed",
  NOT_REPRODUCED: "Refuted by the live test",
  INCONCLUSIVE: "Not tested",
  ERROR: "Error",
};

const OUTCOME_CLASS: Record<AttackOutcome, string> = {
  CONFIRMED: "bad",
  NOT_REPRODUCED: "ok",
  INCONCLUSIVE: "muted",
  ERROR: "warn",
};

const STATE_LABEL: Record<RetestState, string> = {
  BLOCKED: "This exploit no longer reproduces",
  STILL_VULNERABLE: "Still reproduces",
  BROKEN: "Owner access broke",
  GONE: "No longer tested",
  NEW: "New",
  UNCHANGED: "Unchanged",
  ERROR: "Error",
};

const STATE_CLASS: Record<RetestState, string> = {
  BLOCKED: "ok",
  STILL_VULNERABLE: "bad",
  BROKEN: "warn",
  GONE: "muted",
  NEW: "bad",
  UNCHANGED: "muted",
  ERROR: "warn",
};

const CSS = `
:root{--bg:#f7f7f5;--fg:#1c1c1a;--muted:#6b6b66;--card:#fff;--line:#deded8;--bad:#b42318;--ok:#1a7f4b;--warn:#a15c00;--accent:#2b4acb}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ececE8;--muted:#9a9a93;--card:#1e1e1c;--line:#34342f;--bad:#ff7b6e;--ok:#4cc98a;--warn:#f0b24a;--accent:#8aa2ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.sub{color:var(--muted);margin:0 0 20px;font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:28px;line-height:1.1}.tile span{color:var(--muted);font-size:13px}
.tile.bad b{color:var(--bad)}.tile.ok b{color:var(--ok)}
.ledger{color:var(--muted);font-size:13px;margin:10px 0 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.card h3{font-size:16px;margin:0 0 6px}
.badge{display:inline-block;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;border:1px solid currentColor;margin-right:6px}
.badge.bad{color:var(--bad)}.badge.ok{color:var(--ok)}.badge.warn{color:var(--warn)}.badge.muted{color:var(--muted)}
.meta{color:var(--muted);font-size:13px;margin:4px 0}
code,pre{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{color:var(--muted);font-weight:600}
.table-wrap{overflow-x:auto}
details{margin:10px 0}summary{cursor:pointer;color:var(--accent)}
.ba{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
footer{margin-top:32px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:14px}
`;

function ledgerTiles(run: AttackRun): string {
  const l = run.ledger;
  const tile = (n: number, label: string, cls: string) =>
    `<div class="tile ${cls}"><b>${esc(n)}</b><span>${esc(label)}</span></div>`;
  return (
    `<div class="tiles">` +
    tile(l.staticFlagged, "Static flagged", "") +
    tile(l.confirmed, "Live confirmed", l.confirmed > 0 ? "bad" : "") +
    tile(l.refuted, "Refuted", l.refuted > 0 ? "ok" : "") +
    tile(l.untested, "Couldn't test", "") +
    `</div>` +
    `<p class="ledger">Static flagged ${esc(l.staticFlagged)} Â· live confirmed ${esc(l.confirmed)} Â· refuted ${esc(l.refuted)} Â· couldn't test ${esc(l.untested)}` +
    (l.errors > 0 ? ` Â· errors ${esc(l.errors)}` : "") +
    `</p>`
  );
}

function requestsTable(result: AttackResult, group: ProbeGroup | undefined): string {
  if (result.shapes.length === 0) return "";
  const sessionOf = new Map<string, string>();
  for (const r of group?.requests ?? []) sessionOf.set(r.label, r.session ?? "anonymous");
  const rows = result.shapes
    .map((s) => {
      const shape =
        (s.rowCount !== undefined ? `${s.rowCount} row${s.rowCount === 1 ? "" : "s"}; ` : "") +
        (s.keys.length > 0 ? s.keys.map(safeKey).join(", ") : "no keys");
      return `<tr><td>${esc(s.label)}</td><td>${esc(sessionOf.get(s.label) ?? "")}</td><td>${esc(s.status)}</td><td>${esc(shape)}</td></tr>`;
    })
    .join("");
  return `<div class="table-wrap"><table><thead><tr><th>Request</th><th>Session</th><th>Status</th><th>Shape</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function excerpts(result: AttackResult, loopback: boolean): string {
  if (!loopback || !result.excerpts) return "";
  const entries = Object.entries(result.excerpts);
  if (entries.length === 0) return "";
  return (
    `<details><summary>Redacted excerpts (loopback only)</summary>` +
    entries
      .map(
        ([label, text]) =>
          `<p class="meta">${esc(label)}</p><pre>${esc(redactExcerpt(text))}</pre>`,
      )
      .join("") +
    `</details>`
  );
}

function diffBlock(result: AttackResult, diff: RetestDiff | undefined): string {
  if (!diff) return "";
  const was = diff.was ? OUTCOME_LABEL[diff.was] : "not present";
  return (
    `<div class="ba"><span class="badge muted">before: ${esc(was)}</span>` +
    `<span>&rarr;</span>` +
    `<span class="badge ${OUTCOME_CLASS[diff.now]}">after: ${esc(OUTCOME_LABEL[diff.now])}</span>` +
    `<span class="badge ${STATE_CLASS[diff.state]}">${esc(STATE_LABEL[diff.state])}</span>` +
    (diff.ownerOk === true || (diff.ownerOk === undefined && result.ownerOk === true)
      ? `<span class="badge ok">owner access still works &#10003;</span>`
      : "") +
    `</div>`
  );
}

function resultCard(
  result: AttackResult,
  group: ProbeGroup | undefined,
  diff: RetestDiff | undefined,
  loopback: boolean,
): string {
  const ref = result.staticRef;
  const where = result.sourceFile
    ? `${result.sourceFile}${result.line !== undefined ? `:${result.line}` : ""}`
    : ref
      ? `${ref.file}${ref.line !== undefined ? `:${ref.line}` : ""}`
      : "";
  const staticSaid = ref
    ? `<p class="meta"><b>Static said:</b> ${esc(ref.ruleId)} (${esc(ref.findingId)}) at ${esc(where)}: ${esc(ref.title)}</p>`
    : "";
  const live = `<p class="meta"><b>${esc(OUTCOME_LABEL[result.outcome])}:</b> ${esc(result.reasoning)}</p>`;
  const route = result.route
    ? `<p class="meta">Check: ${esc(result.checkId)} Â· Route: ${esc(result.method ?? "GET")} ${esc(result.route)}</p>`
    : `<p class="meta">Check: ${esc(result.checkId)}</p>`;
  const fix =
    result.outcome === "CONFIRMED" && result.fixGuidance
      ? `<p class="meta"><b>Fix:</b> ${esc(result.fixGuidance)}</p>`
      : "";
  const curl =
    result.curl.length > 0
      ? `<details><summary>Replay (curl, placeholders only)</summary><pre>${esc(result.curl.join("\n"))}</pre></details>`
      : "";
  return (
    `<section class="card" id="${esc(result.attackId)}">` +
    `<h3><span class="badge ${OUTCOME_CLASS[result.outcome]}">${esc(result.outcome)}</span>` +
    `${esc(result.attackId)}: ${esc(result.title)}</h3>` +
    route +
    staticSaid +
    live +
    diffBlock(result, diff) +
    requestsTable(result, group) +
    excerpts(result, loopback) +
    fix +
    curl +
    `</section>`
  );
}

function requestLog(run: AttackRun): string {
  if (run.requestLog.length === 0) return "";
  const rows = run.requestLog
    .map(
      (e) =>
        `<tr><td>${esc(e.method)}</td><td>${esc(e.url)}</td><td>${esc(e.status)}</td><td>${esc(e.session ?? "")}</td><td>${esc(e.ms)} ms</td><td>${esc(e.blocked ?? "")}</td></tr>`,
    )
    .join("");
  return (
    `<details><summary>Request log (${run.requestLog.length}, including controls)</summary>` +
    `<div class="table-wrap"><table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Session</th><th>Time</th><th>Blocked</th></tr></thead><tbody>${rows}</tbody></table></div></details>`
  );
}

const SECTIONS: Array<{ outcome: AttackOutcome; title: string }> = [
  { outcome: "CONFIRMED", title: "Live confirmed" },
  { outcome: "NOT_REPRODUCED", title: "Refuted by the live test" },
  { outcome: "INCONCLUSIVE", title: "Not tested" },
  { outcome: "ERROR", title: "Errors" },
];

/** Renders a self-contained HTML report (no external requests). Shapes only, never response values. */
export function renderHtmlReport(run: AttackRun): string {
  const loopback = LOOPBACK_RE.test(run.targetUrl);
  const groups = new Map<string, ProbeGroup>(run.groups.map((g) => [g.attackId, g]));
  const diffs = new Map<string, RetestDiff>((run.diff ?? []).map((d) => [d.attackId, d]));
  const l = run.ledger;
  const heading = `${l.confirmed} confirmed Â· ${l.refuted} refuted Â· ${l.untested} not tested`;

  const body = SECTIONS.map(({ outcome, title }) => {
    const items = run.results.filter((r) => r.outcome === outcome);
    if (items.length === 0) return "";
    return (
      `<h2>${esc(title)} (${items.length})</h2>` +
      items
        .map((r) => resultCard(r, groups.get(r.attackId), diffs.get(r.attackId), loopback))
        .join("")
    );
  }).join("");

  const goneDiffs = (run.diff ?? []).filter(
    (d) => !run.results.some((r) => r.attackId === d.attackId),
  );
  const gone =
    goneDiffs.length > 0
      ? `<h2>No longer present (${goneDiffs.length})</h2>` +
        goneDiffs
          .map(
            (d) =>
              `<section class="card"><div class="ba"><b>${esc(d.attackId)}</b><span class="badge ${STATE_CLASS[d.state]}">${esc(STATE_LABEL[d.state])}</span></div></section>`,
          )
          .join("")
      : "";

  return (
    `<!doctype html>\n<html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>VibeSafe Attack Report</title><style>${CSS}</style></head><body><main>` +
    `<h1>VibeSafe Attack Report: ${esc(heading)}</h1>` +
    `<p class="sub">${esc(run.mode)} run Â· ${esc(run.finishedAt)} Â· target ${esc(run.targetUrl)} Â· VibeSafe ${esc(run.vibesafeVersion)}</p>` +
    ledgerTiles(run) +
    body +
    gone +
    `<h2>Request log</h2>` +
    requestLog(run) +
    `<footer>Attack Mode sends a few safe GET requests to your own app on localhost, aimed by VibeSafe's static findings. ` +
    `It never sends writes, never leaves your machine, and a result of "no longer reproduces" means this exploit was not reproduced, and says nothing about the rest of the app.</footer>` +
    `</main></body></html>\n`
  );
}
