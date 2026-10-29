import type { Confidence, Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import {
  callArgs,
  capPerFile,
  inServerOnlyFunction,
  lineOf,
  loadClientFile,
  outermostSpan,
  useStatePairs,
  wholeLiteral,
  type ClientFile,
} from "./utils/client-source.js";
import { makeFinding } from "./utils/finding.js";
import { calleeBefore, enclosingOpen } from "./utils/js-functions.js";
import type { JsSource } from "./utils/js-source.js";

/**
 * `authorization/client-side-role-check`: a role, admin flag or permission list read from
 * `localStorage`/`sessionStorage` that decides what the user may see or do (compared to a
 * role literal, or used as an `isAdmin`-style condition). Anyone can edit web storage
 * from the devtools console, so the check grants nothing.
 *
 * The read is followed directly, through a `const`/`let` binding, or through a `useState`
 * setter (`setRole(localStorage.getItem("role"))`). Writes and `removeItem` are never
 * flagged; reads that are only displayed are not flagged.
 */

const MAX_PER_FILE = 25;
const READ_RE =
  /\b(localStorage|sessionStorage)\s*(?:\.\s*getItem\s*\(|\.\s*([A-Za-z_$][\w$]*)\b(?!\s*(?:\(|=(?![=>])))|\[\s*(["'`]))/g;
const PREFILTER = /\b(?:localStorage|sessionStorage)\b/;

/** Storage keys or fields that carry a role (normalized: lower case, no separators). */
const ROLE_KEY_RE =
  /^(?:role|roles|userrole|currentrole|accountrole|memberrole|orgrole|isadmin|admin|issuperadmin|superadmin|issuperuser|isstaff|isowner|ismoderator|permission|permissions|userpermissions|accesslevel|usertype|accounttype)$/;
/** Keys that hold a user object whose `.role`/`.isAdmin` field may be checked. */
const USER_KEY_RE = /^(?:user|currentuser|authuser|profile|me|account|session|auth)$/;
/** Role literals that grant elevated access. */
const ROLE_LITERAL_RE =
  /^(?:admin|administrator|owner|superadmin|super_admin|super-admin|superuser|staff|moderator|mod|manager|root|editor|platform_admin|platform-admin)$/i;
const BOOLEAN_ROLE_RE =
  /^(?:isadmin|admin|issuperadmin|superadmin|issuperuser|isstaff|isowner|ismoderator)$/;
const ROLE_FIELD = String.raw`(?:role|roles|isAdmin|is_admin|admin|permissions|isSuperAdmin|isStaff|isOwner|accessLevel|userType)`;

function norm(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export class ClientRoleCheckDetector implements Detector {
  id = "client-role-check-detector";
  name = "Authorization From Browser Storage";
  category = "authorization" as const;
  description =
    "Detects admin or role checks in browser code that trust a role, admin flag or permission list read from localStorage or sessionStorage.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        const cf = await loadClientFile(context, file, { prefilter: (t) => PREFILTER.test(t) });
        if (cf === undefined) continue;
        findings.push(...capPerFile(this.scan(cf), MAX_PER_FILE, (n, f) => summary(f, n)));
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  private scan(cf: ClientFile): Finding[] {
    const { src } = cf;
    const code = src.code;
    const setters = useStatePairs(src);
    const out: Finding[] = [];
    const seen = new Set<number>();
    READ_RE.lastIndex = 0;
    for (let m = READ_RE.exec(code); m !== null; m = READ_RE.exec(code)) {
      if (inServerOnlyFunction(cf, m.index)) continue;
      const read = this.readAt(cf, m);
      if (read === undefined) continue;
      const k = norm(read.key);
      const roleKey = ROLE_KEY_RE.test(k);
      if (!roleKey && !USER_KEY_RE.test(k)) continue;
      // Expression the value flows through: JSON.parse(...) wrapper, then a role field.
      let exprEnd = read.end;
      const open = enclosingOpen(src, read.start);
      if (
        open >= 0 &&
        code[open] === "(" &&
        /^JSON\.parse$/.test(calleeBefore(code, open)?.name ?? "")
      ) {
        const close = src.matchOf(open);
        if (close > 0) exprEnd = close + 1;
      }
      const member = new RegExp(String.raw`^\s*\??\.\s*(${ROLE_FIELD})\b`).exec(
        code.slice(exprEnd, exprEnd + 40),
      );
      let field: string | undefined;
      if (member !== null) {
        field = member[1]!;
        exprEnd += member[0].length;
      } else if (!roleKey) {
        field = undefined; // a user object: its role field is checked through the binding
      }
      const boolean = BOOLEAN_ROLE_RE.test(norm(field ?? read.key));
      const verdict = this.gates(
        cf,
        read.start,
        exprEnd,
        roleKey || field !== undefined,
        boolean,
        setters,
      );
      if (verdict === undefined) continue;
      const line = src.lineAt(m.index);
      if (seen.has(line)) continue;
      seen.add(line);
      out.push(this.finding(cf, m.index, m[1]!, verdict));
    }
    return out;
  }

  /** The storage read at `m`: key text and the read expression's range. */
  private readAt(
    cf: ClientFile,
    m: RegExpExecArray,
  ): { key: string; start: number; end: number } | undefined {
    const { src } = cf;
    const code = src.code;
    if (m[2] !== undefined) {
      if (/^(?:setItem|removeItem|clear|key|length|getItem)$/.test(m[2])) return undefined;
      return { key: m[2], start: m.index, end: m.index + m[0].length };
    }
    if (m[3] !== undefined) {
      const open = code.lastIndexOf("[", m.index + m[0].length);
      const close = src.matchOf(open);
      if (close < 0) return undefined;
      const key = wholeLiteral(src, open + 1, close);
      if (key === undefined) return undefined;
      if (/^\s*=(?![=>])/.test(code.slice(close + 1, close + 4))) return undefined; // a write
      return { key, start: m.index, end: close + 1 };
    }
    const open = m.index + m[0].length - 1;
    const args = callArgs(src, open);
    const close = src.matchOf(open);
    if (args.length === 0 || close < 0) return undefined;
    const key = wholeLiteral(src, args[0]!.start, args[0]!.end);
    if (key === undefined) return undefined;
    return { key, start: m.index, end: close + 1 };
  }

  /**
   * How the role value gates access: compared directly, or via a binding / state variable.
   * `hasRole` is false for a whole user object (only `.role`-style fields of it count).
   */
  private gates(
    cf: ClientFile,
    start: number,
    end: number,
    hasRole: boolean,
    boolean: boolean,
    setters: Map<string, string>,
  ): { confidence: Confidence; how: string } | undefined {
    const { src } = cf;
    const code = src.code;
    if (hasRole && this.comparedAt(src, start, end, boolean)) {
      return { confidence: "high", how: "compared directly" };
    }
    // Binding: `const role = <read>` (possibly `?? "user"`), or `setRole(<read>)`.
    let name: string | undefined;
    let how = "";
    const before = code.slice(Math.max(0, start - 160), start);
    const decl =
      /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]{0,60})?=\s*(?:JSON\s*\.\s*parse\s*\(\s*)?$/.exec(
        before,
      );
    if (decl !== null) {
      name = decl[1]!;
      how = "stored in a variable";
    } else {
      const open = enclosingOpen(src, start);
      const callee = open >= 0 && code[open] === "(" ? calleeBefore(code, open) : undefined;
      const inner =
        callee?.name === "JSON.parse" ? calleeBefore(code, enclosingOpen(src, open)) : callee;
      const state = inner === undefined ? undefined : setters.get(inner.name);
      if (state !== undefined) {
        name = state;
        how = "copied into React state";
      }
    }
    if (name === undefined) return undefined;
    const outer = outermostSpan(cf, start);
    const esc = name.replace(/\$/g, "\\$");
    const use = hasRole
      ? String.raw`(?<![\w$.])${esc}(?![\w$])`
      : String.raw`(?<![\w$.])${esc}\s*\??\.\s*${ROLE_FIELD}\b`;
    const re = new RegExp(use, "g");
    // State is read anywhere in the component; a binding only after its declaration.
    re.lastIndex = how === "copied into React state" ? outer.start : Math.max(outer.start, start);
    for (let m = re.exec(code); m !== null && m.index < outer.end; m = re.exec(code)) {
      const fieldBool =
        !hasRole && /isAdmin|is_admin|admin|isSuperAdmin|isStaff|isOwner/.test(m[0]);
      if (this.comparedAt(src, m.index, m.index + m[0].length, boolean || fieldBool)) {
        return { confidence: "medium", how };
      }
    }
    return undefined;
  }

  /** The expression `[start, end)` is compared to a role literal or used as an admin flag. */
  private comparedAt(src: JsSource, start: number, end: number, boolean: boolean): boolean {
    const code = src.code;
    const after = code.slice(end, end + 120);
    const cmpAfter = /^\s*(?:\?\?\s*["'`][^"'`\n]*["'`]\s*)?[!=]==?\s*(["'`])/.exec(after);
    if (cmpAfter !== null) {
      const text = quoted(src, end + cmpAfter[0].length - 1);
      if (text !== undefined && ROLE_LITERAL_RE.test(text)) return true;
      if (boolean && text !== undefined && /^(?:true|1|yes)$/i.test(text)) return true;
    }
    const before = code.slice(Math.max(0, start - 120), start);
    const cmpBefore = /(["'`])\s*[!=]==?\s*$/.exec(before);
    if (cmpBefore !== null) {
      const closeQ = start - cmpBefore[0].length;
      const openQ = code.lastIndexOf(cmpBefore[1]!, closeQ - 1);
      const text = openQ >= 0 ? quoted(src, openQ) : undefined;
      if (text !== undefined && ROLE_LITERAL_RE.test(text)) return true;
    }
    const inc = /^\s*\??\.\s*(?:includes|indexOf|has|some)\s*\(\s*(["'`])/.exec(after);
    if (inc !== null) {
      const text = quoted(src, end + inc[0].length - 1);
      if (text !== undefined && ROLE_LITERAL_RE.test(text)) return true;
    }
    // `["admin", "owner"].includes(role)`
    const incBefore = /\]\s*\.\s*includes\s*\(\s*$/.exec(before);
    if (incBefore !== null) {
      const close = start - incBefore[0].length;
      const open = src.matchOf(close);
      if (open >= 0 && /admin|owner|staff|moderator|super/i.test(src.text.slice(open, close)))
        return true;
    }
    if (boolean) {
      if (/^\s*(?:&&|\?(?![.?])|===?\s*(?:true|["'`]true))/.test(after)) return true;
      if (/(?:\bif\s*\(\s*!?\s*|!\s*)$/.test(before)) return true;
    }
    return false;
  }

  private finding(
    cf: ClientFile,
    at: number,
    store: string,
    v: { confidence: Confidence; how: string },
  ): Finding {
    const { line, text } = lineOf(cf.src, at);
    return makeFinding({
      category: "authorization",
      ruleId: "authorization/client-side-role-check",
      title: `Access decided by a role stored in ${store}`,
      severity: "high",
      confidence: v.confidence,
      file: cf.file,
      line,
      evidence: text,
      plainEnglishProblem: `This page reads the user's role or admin flag from ${store} (${v.how}) and uses it to decide what the user can see or do. Anyone can change that value in the browser console.`,
      whyItMatters:
        "Running localStorage.setItem('role', 'admin') unlocks the admin UI for any visitor. If the server does not check permissions again on every request, they get admin actions too.",
      fixSteps: [
        "Decide access on the server: read the role from the verified session (or the database) in a server component, middleware or API route.",
        "Make every admin API route and server action check the role itself; never trust a role sent by or stored in the browser.",
        "Use client-side role state only for cosmetic UI, loaded from a server endpoint that checks the session.",
      ],
      aiFixPrompt:
        "This React code decides admin/role access from a value read from localStorage or sessionStorage, which any user can edit. Move the authorization to the server: fetch the current user's role from the verified session or database in a server component, middleware or API route, redirect or return 403 when the role is not allowed, and make every admin API route enforce the same check. Remove the role/admin value from web storage and from the client-side gate.",
    });
  }
}

/** Text of the string literal opening at `quote` (single line). */
function quoted(src: JsSource, quote: number): string | undefined {
  const q = src.code[quote];
  if (q !== '"' && q !== "'" && q !== "`") return undefined;
  const close = src.code.indexOf(q, quote + 1);
  if (close < 0 || src.code.slice(quote, close).includes("\n")) return undefined;
  return src.text.slice(quote + 1, close);
}

function summary(first: Finding, dropped: number): Finding {
  return makeFinding({
    category: "authorization",
    ruleId: "authorization/client-side-role-check",
    title: `${dropped} more role check(s) from browser storage in this file`,
    severity: first.severity,
    confidence: "medium",
    file: first.file,
    discriminator: `summary:${dropped}`,
    plainEnglishProblem: `${first.plainEnglishProblem} The same pattern appears ${dropped} more time(s) in this file.`,
    whyItMatters: first.whyItMatters,
    fixSteps: first.fixSteps,
    aiFixPrompt: first.aiFixPrompt ?? "",
  });
}
