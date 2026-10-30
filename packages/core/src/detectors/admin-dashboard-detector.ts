// ─────────────────────────────────────────────────────────────────────────────
// Admin Dashboard Detector
//
// Queue dashboards (Bull Board, bull-arena, Agendash) mounted on an Express app with no
// auth middleware in front of them: anyone who can reach the path can inspect, retry and
// delete jobs, and job payloads usually contain customer data.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isServerScope } from "./utils/file-kind.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";

const MAX_PER_FILE = 25;
const PREFILTER_RE = /bull-board|bull-arena|agendash|bullboard/i;
const EXPRESS_RE = /from\s*['"]express['"]|require\s*\(\s*['"]express['"]\s*\)/;
const AUTH_LIKE_RE =
  /auth|authenticate|requireUser|requireAdmin|ensureLoggedIn|isAdmin|basicAuth|passport\s*\.\s*authenticate|protect|guard|session/i;
const NONPROD_RE =
  /(?:NODE_ENV|nodeEnv|APP_ENV|ENVIRONMENT)\s*(?:!==|!=)\s*['"`]production['"`]|(?:NODE_ENV|nodeEnv|APP_ENV|ENVIRONMENT)\s*(?:===|==)\s*['"`](?:development|dev|local)['"`]|!\s*(?:isProd|isProduction)\b|(?<!!\s*(?:[\w$]+\s*\.\s*)*)(?<![\w$])isDev(?:elopment)?\b/;
/** An inline middleware function that answers 401/403 is an auth check. */
const INLINE_AUTH_RE = /(?:=>|\bfunction\b)[\s\S]*?(?:\b40[13]\b|[Uu]nauthori[sz]ed|[Ff]orbidden)/;
const isAuthArg = (a: string): boolean => AUTH_LIKE_RE.test(a) || INLINE_AUTH_RE.test(a);

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

interface Call {
  start: number;
  obj: string;
  args: string[];
  /** text of the whole argument list, for the first-arg path check */
  firstIsString: boolean;
}

/** Splits `src[open+1, close)` on top-level commas (using masked code for structure). */
function splitArgs(src: JsSource, open: number, close: number): string[] {
  const out: string[] = [];
  let depth = 0;
  let last = open + 1;
  for (let i = open + 1; i < close; i++) {
    const c = src.code[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) {
      out.push(src.text.slice(last, i).trim());
      last = i + 1;
    }
  }
  const tail = src.text.slice(last, close).trim();
  if (tail.length > 0) out.push(tail);
  return out;
}

function callsOf(src: JsSource, method: string): Call[] {
  const calls: Call[] = [];
  const re = new RegExp(`\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*${method}\\s*\\(`, "g");
  for (let m = re.exec(src.code); m; m = re.exec(src.code)) {
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close <= open) continue;
    const args = splitArgs(src, open, close);
    calls.push({
      start: m.index,
      obj: m[1]!,
      args,
      firstIsString: /^['"`]/.test(args[0] ?? ""),
    });
  }
  return calls;
}

/** Local names an import/require of one of `modules` binds. */
function importedNames(text: string, modules: string): string[] {
  const names: string[] = [];
  const imp = new RegExp(
    `import\\s+(?:([A-Za-z_$][\\w$]*)\\s*,?\\s*)?(?:\\{([^}]*)\\}\\s*)?(?:\\*\\s*as\\s+([A-Za-z_$][\\w$]*)\\s*)?from\\s*['"](?:${modules})(?:/[^'"]*)?['"]`,
    "g",
  );
  for (let m = imp.exec(text); m; m = imp.exec(text)) {
    if (m[1]) names.push(m[1]);
    if (m[3]) names.push(m[3]);
    if (m[2]) {
      for (const part of m[2].split(",")) {
        const n = part
          .split(/\s+as\s+/)
          .pop()!
          .trim();
        if (n) names.push(n);
      }
    }
  }
  const req = new RegExp(
    `(?:const|let|var)\\s+(\\{[^}]*\\}|[A-Za-z_$][\\w$]*)\\s*=\\s*require\\s*\\(\\s*['"](?:${modules})(?:/[^'"]*)?['"]\\s*\\)`,
    "g",
  );
  for (let m = req.exec(text); m; m = req.exec(text)) {
    const pat = m[1]!;
    if (pat.startsWith("{")) {
      for (const part of pat.slice(1, -1).split(",")) {
        const n = part.split(":").pop()!.trim();
        if (n) names.push(n);
      }
    } else names.push(pat);
  }
  return names.filter((n) => /^[A-Za-z_$][\w$]*$/.test(n));
}

/** Source ranges of `if (non-production) ...` consequents. */
function nonProdRanges(src: JsSource): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  const re = /\bif\s*\(/g;
  for (let m = re.exec(src.code); m; m = re.exec(src.code)) {
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close <= open) continue;
    if (!NONPROD_RE.test(src.text.slice(open + 1, close))) continue;
    let i = close + 1;
    while (i < src.code.length && /\s/.test(src.code[i]!)) i++;
    if (src.code[i] === "{") {
      const e = src.matchOf(i);
      out.push([i, e > i ? e : src.code.length]);
    } else {
      let e = i;
      while (e < src.code.length && src.code[e] !== ";" && src.code[e] !== "\n") e++;
      out.push([i, e]);
    }
  }
  return out;
}

export class AdminDashboardDetector implements Detector {
  id = "admin-dashboard-detector";
  name = "Admin Dashboard Exposure Detection";
  category = "auth" as const;
  description =
    "Detects queue dashboards (Bull Board, bull-arena, Agendash) mounted on an Express app without authentication.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        const text = await context.readFile(file);
        if (!text || text.length > 600_000 || !PREFILTER_RE.test(text)) continue;
        const cls = classifyFile(file, text, context.projectContext);
        if (!isServerScope(cls) || cls.testOrFixture || cls.generated) continue;
        const isFastify = /@bull-board\/fastify/.test(text);
        if (!EXPRESS_RE.test(text) && !isFastify) continue;
        const src = await getJsSource(context, file);
        findings.push(...this.scan(src, file, text, isFastify));
      } catch {
        // detectors never throw
      }
    }
    return findings;
  }

  private scan(src: JsSource, file: string, text: string, isFastify: boolean): Finding[] {
    // Names whose value is a dashboard router, and regexes for inline dashboard expressions.
    const names = new Set<string>();
    const boardCalls = importedNames(text, "bull-board|@bull-board/api|@bull-board/express").filter(
      (n) => n === "createBullBoard",
    );
    const arena = importedNames(text, "bull-arena");
    const agendash = importedNames(text, "agendash");
    const adapterClasses = importedNames(text, "@bull-board/express|@bull-board/fastify").filter(
      (n) => /Adapter$/.test(n),
    );
    const exprParts: string[] = [];
    if (boardCalls.length > 0) {
      for (const b of boardCalls)
        exprParts.push(`${escapeRe(b)}\\s*\\([\\s\\S]{0,400}?\\)\\s*\\.\\s*router`);
    }
    for (const a of [...arena, ...agendash]) exprParts.push(`${escapeRe(a)}\\s*\\(`);
    const adapters = new Set<string>();
    for (const cls of adapterClasses) {
      const re = new RegExp(
        `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=;]*)?=\\s*new\\s+${escapeRe(cls)}\\s*\\(`,
        "g",
      );
      for (let m = re.exec(src.code); m; m = re.exec(src.code)) adapters.add(m[1]!);
    }
    for (const a of adapters) {
      exprParts.push(`${escapeRe(a)}\\s*\\.\\s*getRouter\\s*\\(`);
    }
    // bindings: const { router: X } = createBullBoard(...), const X = createBullBoard(...), const X = Arena(...)
    for (const b of boardCalls) {
      const destructured = new RegExp(
        `(?:const|let|var)\\s+\\{([^}]*)\\}\\s*=\\s*(?:await\\s+)?${escapeRe(b)}\\s*\\(`,
        "g",
      );
      for (let m = destructured.exec(src.code); m; m = destructured.exec(src.code)) {
        const fields =
          src.text.slice(m.index, m.index + m[0].length).match(/\{([^}]*)\}/)?.[1] ?? "";
        for (const part of fields.split(",")) {
          const [key, alias] = part.split(":").map((s) => s.trim());
          if (key === "router") names.add(alias || "router");
        }
      }
      const whole = new RegExp(
        `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=;]*)?=\\s*(?:await\\s+)?${escapeRe(b)}\\s*\\(`,
        "g",
      );
      for (let m = whole.exec(src.code); m; m = whole.exec(src.code)) {
        // `X.router` is the dashboard; record the object under a marker
        names.add(`${m[1]!}.router`);
      }
    }
    const exprRe = exprParts.length > 0 ? new RegExp(exprParts.join("|")) : undefined;
    const bindRe = exprRe
      ? new RegExp(
          `(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=;]*)?=\\s*(?:await\\s+)?(?:${exprParts.join("|")})`,
          "g",
        )
      : undefined;
    if (bindRe) {
      for (let m = bindRe.exec(src.text); m; m = bindRe.exec(src.text)) {
        if (src.code[m.index] === "c" || src.code[m.index] === "l" || src.code[m.index] === "v") {
          names.add(m[1]!);
        }
      }
    }
    if (exprRe === undefined && names.size === 0) return [];

    const isDashboard = (arg: string): boolean => {
      const a = arg.trim().replace(/^await\s+/, "");
      if (names.has(a)) return true;
      if (/^[A-Za-z_$][\w$]*$/.test(a)) return false;
      if ([...names].some((n) => n === a)) return true;
      return exprRe !== undefined && exprRe.test(a);
    };

    const uses = callsOf(src, "use");
    const regs = isFastify ? callsOf(src, "register") : [];
    const ranges = nonProdRanges(src);
    const out: Finding[] = [];
    const emit = (start: number, obj: string): void => {
      const line = src.lineAt(start);
      out.push(
        makeFinding({
          category: "auth",
          ruleId: "auth/unprotected-queue-dashboard",
          title: "Queue dashboard is mounted without authentication",
          severity: "high",
          confidence: exportedRouters.has(obj) ? "medium" : "high",
          file,
          line,
          evidence: src.lineText(line),
          discriminator: `${obj}:${line}`,
          plainEnglishProblem:
            "A job-queue admin dashboard is mounted on the web server with no authentication middleware in front of it, so anyone who can reach this path can use it.",
          whyItMatters:
            "Queue dashboards show job payloads (often customer emails, tokens and documents) and let visitors retry, promote or delete jobs. An exposed one is a data leak and a way to run or disrupt background work.",
          fixSteps: [
            "Put an authentication and admin-role middleware before the dashboard: app.use('/admin/queues', requireAdmin, dashboardRouter).",
            "Or register an auth middleware globally before the mount.",
            "If it is for local debugging only, mount it only when NODE_ENV is not production and bind it to localhost.",
          ],
          aiFixPrompt:
            "This Express app mounts a queue dashboard (Bull Board, bull-arena or Agendash) without any authentication. Add an authentication middleware that also checks an admin role (or HTTP basic auth with credentials from the environment) in front of the dashboard router, and make sure it runs before the mount. Do not expose the dashboard in production without it.",
        }),
      );
    };

    const authBefore = (obj: string, at: number): boolean =>
      uses.some(
        (u) =>
          u.obj === obj &&
          u.start < at &&
          (u.args.length === 1 || (u.firstIsString && /^['"`]\/?\*?['"`]$/.test(u.args[0]!))) &&
          u.args.slice(u.firstIsString ? 1 : 0).some(isAuthArg),
      );

    // `export const router = express.Router()`: it may be mounted behind auth in another module
    const exportedRouters = new Set<string>();
    for (const m of src.code.matchAll(
      /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]*)?=\s*(?:express\s*\.\s*)?Router\s*\(/g,
    )) {
      const n = m[1]!;
      const e = escapeRe(n);
      if (
        new RegExp(
          `export\\s+(?:const|let|var)\\s+${e}\\b|export\\s+default\\s+${e}\\b|module\\s*\\.\\s*exports\\s*=\\s*${e}\\b|\\bexports\\s*\\.\\s*[\\w$]+\\s*=\\s*${e}\\b|export\\s*\\{[^}]*\\b${e}\\b`,
        ).test(src.code)
      ) {
        exportedRouters.add(n);
      }
    }

    for (const u of uses) {
      if (out.length >= MAX_PER_FILE) break;
      const argStart = u.firstIsString ? 1 : 0;
      const idx = u.args.findIndex((a, i) => i >= argStart && isDashboard(a));
      if (idx < 0) continue;
      if (ranges.some(([a, b]) => u.start >= a && u.start < b)) continue;
      const earlierArgs = u.args.slice(argStart, idx);
      if (earlierArgs.some(isAuthArg)) continue;
      if (authBefore(u.obj, u.start)) continue;
      emit(u.start, u.obj);
    }
    for (const r of regs) {
      if (out.length >= MAX_PER_FILE) break;
      const first = r.args[0] ?? "";
      const m = /^([A-Za-z_$][\w$]*)\s*\.\s*registerPlugin\s*\(/.exec(first);
      if (!m || !adapters.has(m[1]!)) continue;
      if (ranges.some(([a, b]) => r.start >= a && r.start < b)) continue;
      if (r.args.slice(1).some((a) => AUTH_LIKE_RE.test(a) || /preHandler|onRequest/.test(a)))
        continue;
      const hooks = callsOf(src, "addHook");
      if (
        hooks.some(
          (h) => h.obj === r.obj && h.start < r.start && h.args.some((a) => AUTH_LIKE_RE.test(a)),
        )
      ) {
        continue;
      }
      emit(r.start, r.obj);
    }
    return out;
  }
}
