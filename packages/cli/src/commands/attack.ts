import path from "node:path";
import { pathToFileURL } from "node:url";
import chalk from "chalk";
import open from "open";
import type {
  AttackResult,
  AttackRun,
  ProbeGroup,
  ResponseShape,
  RetestDiff,
  RunOptions,
} from "@talaljaber/vibesafe-attack";
import type * as AttackPkg from "@talaljaber/vibesafe-attack";
import { sanitizeTerminal } from "../ui/sanitize.js";

type AttackModule = typeof AttackPkg;

export interface AttackCommandOptions {
  target?: string | undefined;
  sessions?: string | undefined;
  retest?: boolean | undefined;
  newBaseline?: boolean | undefined;
  dryRun?: boolean | undefined;
  replay?: string | undefined;
  rate?: string | undefined;
  openReport?: boolean | undefined;
  json?: boolean | undefined;
}

/** Errors thrown by the attack package for usage problems carry `exitCode: 2`. */
function isUsageError(err: unknown): err is Error & { exitCode: 2 } {
  return err instanceof Error && (err as { exitCode?: unknown }).exitCode === 2;
}

/** One safe, single-line string for terminal output of repo- or response-controlled text. */
function clean(text: string, max = 160): string {
  const s = sanitizeTerminal(text).replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function usage(message: string, json: boolean): void {
  console.error(json ? `Error: ${message}` : chalk.red(`Error: ${message}`));
  process.exitCode = 2;
}

/** Parses --rate; undefined when absent, NaN when not a number (the runner rejects it). */
export function parseRate(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  return value.trim() === "" ? Number.NaN : n;
}

export async function runAttackCommand(dir: string, options: AttackCommandOptions): Promise<void> {
  const json = Boolean(options.json);
  const root = path.resolve(dir);

  if (options.retest && options.newBaseline) {
    return usage("--retest and --new-baseline cannot be used together.", json);
  }
  if (options.replay !== undefined && (options.retest || options.newBaseline)) {
    return usage("--replay cannot be combined with --retest or --new-baseline.", json);
  }

  const rate = parseRate(options.rate);
  const log = (line: string): void => {
    // Progress goes to stderr in --json mode so stdout stays pure JSON.
    if (json) console.error(clean(line, 300));
    // Static-scan coverage notes (unsupported files) are not about the attack; keep the screen calm.
    else if (line.startsWith("Static scan: Not scanned")) return;
    else console.log(chalk.gray(`  › ${clean(line, 300)}`));
  };
  const runOptions: RunOptions = {
    projectPath: root,
    target: options.target,
    sessionsPath: options.sessions,
    mode: options.dryRun ? "dry-run" : options.retest ? "retest" : "baseline",
    newBaseline: Boolean(options.newBaseline),
    rate,
    log,
  };

  let attack: AttackModule;
  try {
    // Loaded lazily so `vibesafe scan` never pays for Attack Mode at startup.
    attack = await import("@talaljaber/vibesafe-attack");
  } catch (err) {
    return usage(
      `could not load Attack Mode: ${clean(err instanceof Error ? err.message : String(err))}`,
      json,
    );
  }

  if (!json) printIntro(runOptions, options.replay);

  try {
    if (options.replay !== undefined) {
      const result = await attack.replayAttack(runOptions, options.replay);
      if (json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printReplay(result);
      }
      process.exitCode = result.outcome === "CONFIRMED" ? 1 : 0;
      return;
    }

    const run = await attack.runAttack(runOptions);
    const code = attack.exitCodeForRun(run);
    const htmlPath = path.join(root, attack.VIBESAFE_DIR, attack.REPORT_HTML_FILE);
    const mdPath = `${attack.VIBESAFE_DIR}/${attack.REPORT_MD_FILE}`;

    if (json) {
      console.log(JSON.stringify(run, null, 2));
    } else {
      printRun(
        run,
        attack.renderTerminalSummary(run, { htmlReportPath: htmlPath, markdownReportPath: mdPath }),
      );
    }

    if (options.openReport && run.mode !== "dry-run") {
      try {
        await open(pathToFileURL(htmlPath).href);
      } catch {
        const msg = "Could not open the report in your browser.";
        if (json) console.error(msg);
        else console.log(chalk.gray(msg));
      }
    }
    process.exitCode = code;
  } catch (err) {
    const message = clean(err instanceof Error ? err.message : String(err), 400);
    if (isUsageError(err)) {
      usage(message, json);
    } else {
      console.error(
        json ? `Attack failed: ${message}` : chalk.red.bold(`\nAttack failed: ${message}`),
      );
      process.exitCode = 2;
    }
  }
}

// ---------------------------------------------------------------- terminal output

const RULE = "─".repeat(64);

function printIntro(o: RunOptions, replay: string | undefined): void {
  const what =
    replay !== undefined
      ? `Replaying ${clean(replay, 40)}`
      : o.mode === "retest"
        ? "Retest: replaying every baseline attack against your fixed app"
        : o.mode === "dry-run"
          ? "Dry run: planning requests, sending nothing"
          : "Proving static findings with live, safe requests";
  console.log(chalk.bold.magenta("\n⚔  VibeSafe Attack Mode"));
  console.log(chalk.white(`   ${what}`));
  console.log(
    chalk.gray(
      "   Safe by design: your local dev server only (loopback), GET only, no request bodies, rate limited, 300 requests max.\n",
    ),
  );
}

function sessionOf(group: ProbeGroup | undefined, label: string): string | undefined {
  const s = group?.requests.find((r) => r.label === label)?.session;
  return s !== undefined && /^[\w.-]{1,32}$/.test(s) ? s : undefined;
}

function cap(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

function nounOf(result: AttackResult): string {
  const m = /user's (.+?)\.?$/.exec(result.title)?.[1] ?? "record";
  const noun = clean(m, 40).replace(/ \(not tested\)$/, "");
  // "notes" -> "note": the demo proves one record, so say it in the singular.
  return noun.length > 3 && noun.endsWith("s") && !noun.endsWith("ss") ? noun.slice(0, -1) : noun;
}

function shape(result: AttackResult, label: string): ResponseShape | undefined {
  return result.shapes.find((s) => s.label === label);
}

function keysText(s: ResponseShape | undefined): string {
  if (!s || s.keys.length === 0) return "";
  const keys = s.keys.slice(0, 6).map((k) => clean(k, 64));
  const more = s.keys.length > 6 ? ", …" : "";
  const rows = s.rowCount !== undefined ? `${s.rowCount} rows, ` : "";
  return ` (${rows}keys: ${keys.join(", ")}${more})`;
}

/** The human headline for a CONFIRMED result, e.g. "Alice read Bob's note." */
export function headline(result: AttackResult, group: ProbeGroup | undefined): string {
  if (result.checkId === "idor") {
    const attacker = sessionOf(group, "R3") ?? "one user";
    const owner = sessionOf(group, "R2") ?? "another user";
    const noun = nounOf(result);
    if (result.severity === "critical") return `Anyone, logged out, read ${cap(owner)}'s ${noun}.`;
    return `${cap(attacker)} read ${cap(owner)}'s ${noun}.`;
  }
  if (result.checkId === "unauth-route") {
    return `A logged-out visitor read ${result.method ?? "GET"} ${clean(result.route ?? "this route", 80)}.`;
  }
  return clean(result.title, 100);
}

/** The evidence line under a headline: who asked for what, and what came back (shapes only). */
export function evidence(result: AttackResult, group: ProbeGroup | undefined): string[] {
  const out: string[] = [];
  if (result.checkId === "idor" && result.shapes.length > 0) {
    const attacker = sessionOf(group, "R3") ?? "attacker";
    const owner = sessionOf(group, "R2") ?? "owner";
    const r0 = shape(result, "R0");
    const r2 = shape(result, "R2");
    const r3 = shape(result, "R3");
    if (r3) out.push(`${attacker} → ${owner}'s ${nounOf(result)}: ${r3.status}${keysText(r3)}`);
    if (r2) out.push(`${owner} → own ${nounOf(result)}: ${r2.status}${keysText(r2)}`);
    if (r0) out.push(`logged out: ${r0.status}`);
  } else if (result.checkId === "unauth-route" && result.shapes.length > 0) {
    const u1 = shape(result, "U1");
    const u2 = shape(result, "U2");
    const who = sessionOf(group, "U2") ?? "signed in";
    if (u1) out.push(`logged out: ${u1.status}${keysText(u1)}`);
    if (u2) out.push(`${who}: ${u2.status}`);
  }
  return out;
}

function location(result: AttackResult): string {
  const route = result.route ? `${result.method ?? "GET"} ${clean(result.route, 80)}` : "";
  const src = result.sourceFile
    ? `${clean(result.sourceFile, 80)}${result.line !== undefined ? `:${result.line}` : ""}`
    : "";
  return [route, src, clean(result.attackId, 40)].filter(Boolean).join("  ·  ");
}

function printBaselineHighlights(run: AttackRun): void {
  const groupOf = (id: string): ProbeGroup | undefined => run.groups.find((g) => g.attackId === id);
  const order = { CONFIRMED: 0, ERROR: 1, NOT_REPRODUCED: 2, INCONCLUSIVE: 3 } as const;
  const results = [...run.results].sort((a, b) => order[a.outcome] - order[b.outcome]);
  for (const r of results) {
    const g = groupOf(r.attackId);
    if (r.outcome === "CONFIRMED") {
      console.log(
        `${chalk.bgRed.white.bold(" CONFIRMED ")} ${chalk.red.bold(clean(headline(r, g), 120))}`,
      );
    } else if (r.outcome === "NOT_REPRODUCED") {
      console.log(
        `${chalk.bgGreen.black.bold(" REFUTED   ")} ${chalk.green(`Static flagged it, but ${refutedText(r, g)}.`)}`,
      );
    } else if (r.outcome === "INCONCLUSIVE") {
      console.log(`${chalk.bgGray.white.bold(" NOT TESTED")} ${chalk.gray(clean(r.title, 100))}`);
    } else {
      console.log(
        `${chalk.bgYellow.black.bold(" ERROR     ")} ${chalk.yellow(clean(r.title, 100))}`,
      );
    }
    console.log(chalk.gray(`            ${location(r)}`));
    const lines =
      r.outcome === "INCONCLUSIVE" || r.outcome === "ERROR"
        ? [clean(r.reasoning, 140)]
        : evidence(r, g);
    for (const l of lines) console.log(chalk.white(`            ${l}`));
    if (r.outcome === "CONFIRMED" && r.ownerOk && r.checkId === "idor") {
      console.log(chalk.gray("            owner access works (the rightful user gets 200)"));
    }
    console.log("");
  }
}

const STATE_BADGE: Record<RetestDiff["state"], (s: string) => string> = {
  BLOCKED: (s) => chalk.bgGreen.black.bold(s),
  STILL_VULNERABLE: (s) => chalk.bgRed.white.bold(s),
  NEW: (s) => chalk.bgRed.white.bold(s),
  BROKEN: (s) => chalk.bgYellow.black.bold(s),
  GONE: (s) => chalk.bgYellow.black.bold(s),
  ERROR: (s) => chalk.bgYellow.black.bold(s),
  UNCHANGED: (s) => chalk.bgGray.white.bold(s),
};

function printRetestHighlights(run: AttackRun): void {
  const groupOf = (id: string): ProbeGroup | undefined => run.groups.find((g) => g.attackId === id);
  const rank: Record<RetestDiff["state"], number> = {
    BLOCKED: 0,
    STILL_VULNERABLE: 1,
    NEW: 2,
    BROKEN: 3,
    GONE: 4,
    ERROR: 5,
    UNCHANGED: 6,
  };
  const diffs = [...(run.diff ?? [])].sort((a, b) => rank[a.state] - rank[b.state]);
  for (const d of diffs) {
    const r = run.results.find((x) => x.attackId === d.attackId);
    if (!r) continue;
    const g = groupOf(r.attackId);
    const badge = STATE_BADGE[d.state](` ${d.state.replace("_", " ").padEnd(16)} `);
    let text: string;
    if (d.state === "BLOCKED") {
      text = chalk.green.bold(`Fixed: ${blockedText(r, g)}`);
    } else if (d.state === "STILL_VULNERABLE" || d.state === "NEW") {
      text = chalk.red.bold(headline(r, g));
    } else if (d.state === "BROKEN") {
      text = chalk.yellow.bold("The attacker is denied, but the owner lost access too.");
    } else if (d.state === "GONE") {
      text = chalk.yellow("The route is gone (404 for the owner too). Not counted as a fix.");
    } else if (d.state === "UNCHANGED") {
      text = chalk.gray(
        r.outcome === "NOT_REPRODUCED"
          ? `Still refuted by the live test: ${refutedText(r, g)}.`
          : clean(r.title, 100),
      );
    } else {
      text = chalk.yellow(clean(r.reasoning, 100));
    }
    console.log(`${badge} ${text}`);
    console.log(chalk.gray(`                   ${location(r)}`));
    const ev = d.state === "UNCHANGED" ? [] : evidence(r, g);
    for (const l of ev) console.log(chalk.white(`                   ${l}`));
    if (d.state === "BLOCKED" && d.ownerOk) {
      console.log(chalk.green.bold("                   owner access still works ✓"));
    }
    console.log("");
  }
}

/** Why the static claim did not hold, e.g. "Alice was refused Bob's invoice (404)". */
function refutedText(r: AttackResult, g: ProbeGroup | undefined): string {
  if (r.checkId === "idor") {
    const attacker = sessionOf(g, "R3") ?? "the attacker";
    const owner = sessionOf(g, "R2") ?? "the owner";
    const st = shape(r, "R3")?.status;
    return `${cap(attacker)} was refused ${cap(owner)}'s ${nounOf(r)}${st !== undefined ? ` (${st})` : ""}`;
  }
  return `the live test says safe: ${clean(r.title, 90)}`;
}

function blockedText(r: AttackResult, g: ProbeGroup | undefined): string {
  if (r.checkId === "idor") {
    const attacker = sessionOf(g, "R3") ?? "the attacker";
    const owner = sessionOf(g, "R2") ?? "the owner";
    const st = shape(r, "R3")?.status;
    return `${cap(attacker)} can no longer read ${cap(owner)}'s ${nounOf(r)}${st !== undefined ? ` (now ${st})` : ""}.`;
  }
  if (r.checkId === "unauth-route") {
    const st = shape(r, "U1")?.status;
    return `Logged-out visitors are refused${st !== undefined ? ` (now ${st})` : ""}.`;
  }
  return clean(r.title, 100);
}

function printRun(run: AttackRun, summary: string[]): void {
  console.log("");
  console.log(chalk.gray(RULE));
  if (run.mode === "dry-run") {
    console.log(chalk.bold(`Dry run: ${run.groups.length} attack groups planned, nothing sent.`));
    for (const g of run.groups) {
      const n = g.skip ? `skipped: ${clean(g.skip.reason, 80)}` : `${g.requests.length} requests`;
      console.log(chalk.gray(`  ${clean(g.attackId, 40)}  ${clean(g.title, 70)}  (${n})`));
    }
    console.log(
      chalk.gray(
        `  ${run.requestLog.length} requests would be sent to ${clean(run.targetUrl, 80)}`,
      ),
    );
    process.stdout.write("\n");
    return;
  }
  if (run.mode === "retest") printRetestHighlights(run);
  else printBaselineHighlights(run);
  console.log(chalk.gray(RULE));

  const [ledger, ...rest] = summary.map((l) => sanitizeTerminal(l));
  console.log(chalk.bold.white(`  ${ledger ?? ""}`));
  console.log(
    chalk.gray(
      `  ${run.requestLog.length} live requests to ${clean(run.targetUrl, 80)} in ${elapsed(run)}`,
    ),
  );
  console.log("");
  for (const line of rest) {
    if (line.startsWith("Tell your agent")) console.log(chalk.cyan.bold(`  ${line}`));
    else if (line.startsWith("HTML report")) console.log(chalk.cyan(`  ${line}`));
    else if (line.startsWith("Errors")) console.log(chalk.yellow(`  ${line}`));
    // The per-result table repeats the cards above, so it is not printed here.
  }
  if (run.mode === "baseline" && run.ledger.confirmed > 0) {
    console.log(chalk.gray("  After the fix, run: vibesafe attack --retest"));
  }
}

function elapsed(run: AttackRun): string {
  const ms = Date.parse(run.finishedAt) - Date.parse(run.startedAt);
  return Number.isFinite(ms) ? `${(ms / 1000).toFixed(1)}s` : "?";
}

function printReplay(result: AttackResult): void {
  console.log(chalk.gray(RULE));
  const color = result.outcome === "CONFIRMED" ? chalk.red.bold : chalk.green.bold;
  console.log(color(`${result.outcome}  ${clean(result.title, 100)}`));
  console.log(chalk.gray(`  ${location(result)}`));
  console.log(chalk.white(`  ${clean(result.reasoning, 200)}`));
  for (const s of result.shapes) {
    console.log(chalk.gray(`  ${clean(s.label, 16)}: ${s.status}${keysText(s)}`));
  }
  if (result.ownerOk) console.log(chalk.green("  owner access works ✓"));
}
