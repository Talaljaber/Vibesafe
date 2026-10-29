// ─────────────────────────────────────────────────────────────────────────────
// Django Views Detector
//
// Flags Django and Django REST Framework views that change data (POST / PUT /
// PATCH / DELETE) without any sign of authentication, and DRF write views that
// explicitly allow anyone (permission_classes = [AllowAny]).
//
// Line/statement based by design (no Python AST): top-level `def` / `class`
// blocks are found by indentation, bodies are matched with regexes.
//
// Known limits:
//  - Only top-level functions and classes in views.py, api.py and views/*.py
//    are considered; views defined elsewhere are not.
//  - Base classes are resolved inside the same file only. A view whose base is
//    imported from another module is still checked, with low confidence.
//  - Auth applied outside the view (custom middleware, URL include() wrappers,
//    API gateways) is not seen, except Django's LoginRequiredMiddleware, the DRF
//    DEFAULT_PERMISSION_CLASSES setting and login_required(...) wrappers in urls.py.
//  - Views named like public auth flows (login, signup, password reset, token
//    obtain/refresh, email verification, webhooks, OAuth callbacks, health checks,
//    contact forms) are skipped; the names are anchored, so confirm_order or
//    update_password are still checked.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import {
  isDevOnlySettings,
  isSettingsFile,
  pythonStatements,
  scanPythonLines,
  type PythonStatement,
} from "./utils/python-source.js";

const MISSING_AUTH_RULE = "auth/django-view-missing-auth";
const ALLOW_ANY_RULE = "auth/django-drf-allow-any";

const DJANGO_IMPORT_RE = /^\s*(?:from|import)\s+(?:django|rest_framework)\b/m;

const DRF_VIEW_BASES = new Set([
  "APIView",
  "GenericAPIView",
  "ViewSet",
  "GenericViewSet",
  "ModelViewSet",
  "ReadOnlyModelViewSet",
  "ViewSetMixin",
  "ListAPIView",
  "RetrieveAPIView",
  "CreateAPIView",
  "ListCreateAPIView",
  "UpdateAPIView",
  "DestroyAPIView",
  "RetrieveUpdateAPIView",
  "RetrieveDestroyAPIView",
  "RetrieveUpdateDestroyAPIView",
  "CreateModelMixin",
  "UpdateModelMixin",
  "DestroyModelMixin",
  "ListModelMixin",
  "RetrieveModelMixin",
]);
/** DRF bases that expose write endpoints without any extra code. */
const DRF_WRITE_BASES = new Set([
  "ModelViewSet",
  "CreateAPIView",
  "ListCreateAPIView",
  "UpdateAPIView",
  "DestroyAPIView",
  "RetrieveUpdateAPIView",
  "RetrieveDestroyAPIView",
  "RetrieveUpdateDestroyAPIView",
  "CreateModelMixin",
  "UpdateModelMixin",
  "DestroyModelMixin",
]);
const DJANGO_VIEW_BASES = new Set([
  "View",
  "TemplateView",
  "RedirectView",
  "DetailView",
  "ListView",
  "FormView",
  "CreateView",
  "UpdateView",
  "DeleteView",
  "BaseCreateView",
  "BaseUpdateView",
  "BaseDeleteView",
  "BaseFormView",
  "ProcessFormView",
  "DeletionMixin",
]);
/** Django generic views that write to the database on POST. */
const DJANGO_WRITE_BASES = new Set([
  "CreateView",
  "UpdateView",
  "DeleteView",
  "BaseCreateView",
  "BaseUpdateView",
  "BaseDeleteView",
  "DeletionMixin",
]);
/** Harmless helpers that are neither views nor auth (they do not lower confidence). */
const NEUTRAL_BASES = new Set([
  "object",
  "SuccessMessageMixin",
  "ContextMixin",
  "TemplateResponseMixin",
  "SingleObjectMixin",
  "MultipleObjectMixin",
  "FormMixin",
  "ModelFormMixin",
  "SingleObjectTemplateResponseMixin",
]);

/** LoginRequiredMixin, PermissionRequiredMixin, UserPassesTestMixin, StaffRequiredMixin, ... */
const AUTH_MIXIN_RE =
  /^(?:\w*(?:Login|Permission|Auth|Staff|Superuser|Admin|Member)\w*Mixin|UserPassesTestMixin|AccessMixin|\w*Required\w*Mixin)$/;

/** Imported project base classes whose name says they enforce auth. */
const AUTH_BASE_NAME_RE =
  /Auth(?!or)|Login|Permission|Protected|Secure|Private|Staff|Superuser|Admin|Member|Owner/;

/** Auth decorators:@login_required, @permission_required(...), @user_passes_test(...), @jwt_required, ... */
const AUTH_DECORATOR_RE =
  /\b(?:\w+_required|user_passes_test|authentication_classes|requires?_(?:auth|login|user|staff|admin)\w*|is_authenticated|authenticated)\b/i;
/** Explicit checks inside a view body. */
const BODY_AUTH_RE =
  /\brequest\.user\.(?:is_authenticated|is_anonymous|is_staff|is_superuser|has_perms?\b)|\braise\s+(?:\w+\.)*PermissionDenied\b|\bredirect_to_login\s*\(|\bHttpResponseForbidden\b|\bcheck_(?:object_)?permissions\s*\(|\bauthenticate\s*\(/;

const WRITE_METHOD_RE = /['"](?:POST|PUT|PATCH|DELETE)['"]/i;
const BODY_WRITE_RE =
  /\brequest\.method\s*(?:==|!=|\bin\b|\bnot\s+in\b)[^:\n]*['"](?:POST|PUT|PATCH|DELETE)['"]|['"](?:POST|PUT|PATCH|DELETE)['"]\s*(?:==|!=)\s*(?:self\.)?request\.method|\brequest\.(?:POST|FILES)\b/;
const WRITE_HANDLER_RE = /^\s*(?:async\s+)?def\s+(post|put|patch|delete)\s*\(/;
const VIEWSET_WRITE_ACTION_RE =
  /^\s*(?:async\s+)?def\s+(create|update|partial_update|destroy)\s*\(/;
const HTTP_HANDLER_RE =
  /^\s*(?:async\s+)?def\s+(?:get|post|put|patch|delete|head|options)\s*\(\s*self\s*,\s*request\b/;

/**
 * Views that are public by nature, matched on the snake_case name without a trailing
 * `_view` / `_api_view` / `_viewset`. Anchored so that ordinary write views such as
 * confirm_order, reset_project, update_password or delete_token are still checked.
 */
const PUBLIC_VIEW_NAME_RES = [
  // Login, logout, sign-up and registration flows.
  /^(?:(?:user|account|api|custom)_)?(?:log_?in|log_?out|sign_?in|sign_?out|sign_?up|register|registration)(?:_|$)/,
  // Forgotten-password reset (not changing or updating a password while logged in).
  /^(?:(?:user|account|api)_)?(?:password_reset|reset_password|forgot_password|password_forgot)(?:_|$)/,
  // JWT / token login endpoints.
  /^(?:jwt_)?token_(?:obtain|refresh|verify|blacklist)(?:_|$)|^(?:obtain|refresh)_(?:jwt_|auth_)?token$/,
  // Email verification and account activation links.
  /^(?:verify|confirm|resend)_(?:email|verification)|^email_(?:verify|verification|confirm)|^activate(?:_(?:account|user|email))?$|^account_activation/,
  // Webhooks, OAuth / SSO callbacks and health checks.
  /(?:^|_)webhooks?(?:_|$)|(?:^|_)(?:oauth2?|sso|saml)(?:_|$)|(?:^|_)callback$|^health(?:_?check)?$/,
  // Public contact and newsletter forms, by exact name only.
  /^(?:contact(?:_us|_form)?|(?:newsletter_)?(?:un)?subscribe|newsletter(?:_sign_?up)?)$/,
];

/** CamelCase or snake_case view name to snake_case, minus a trailing view suffix. */
function publicNameKey(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .replace(/(?:_api)?_(?:view_?set|view|api)$/, "");
}

/**
 * Management or privileged actions that are never public, even when the name also mentions a
 * public flow: create_webhook, SSOSettingsView, login_as_user, register_device, registration_approve.
 */
const MANAGEMENT_NAME_RE =
  /(?:^|_)(?:create|add|update|edit|delete|remove|manage|settings?|config|configure|admin|impersonate|approve|invite|device)(?:_|$)|(?:^|_)as_user(?:_|$)/;

function isPublicViewName(name: string): boolean {
  const key = publicNameKey(name);
  if (MANAGEMENT_NAME_RE.test(key)) return false;
  return PUBLIC_VIEW_NAME_RES.some((re) => re.test(key));
}

type PermissionKind = "auth" | "allowAny" | "none";

interface ViewInfo {
  name: string;
  line: number;
  head: string;
  isView: boolean;
  isDrf: boolean;
  writes: boolean;
  auth: boolean;
  /** Explicit permission_classes on the view (or an in-file parent). */
  permission?: PermissionKind | undefined;
  loginNotRequired: boolean;
  unknownBase: boolean;
}

interface ProjectAuth {
  drfDefaultProtected: boolean;
  loginRequiredMiddleware: boolean;
  /** View names wrapped in login_required(...) and friends in urls.py. */
  wrapped: Set<string>;
}

function isViewFile(filePath: string): boolean {
  const parts = filePath.replace(/\\/g, "/").split("/");
  const fileName = parts.pop() ?? "";
  if (!fileName.endsWith(".py")) return false;
  return fileName === "views.py" || fileName === "api.py" || parts.includes("views");
}

/** Classifies a permission_classes value: `[AllowAny]`, `[]` or anything else. */
function permissionKind(value: string): PermissionKind {
  // Only a literal list/tuple; `get_perms()` or `base.perms + [X]` is a call or expression.
  const list = /^\s*[[(]([^\])]*)[\])]/.exec(value);
  if (!list) return "auth"; // a variable or call: assume it enforces something
  const entries = (list[1] ?? "")
    .split(",")
    .map((e) => e.trim().replace(/^['"]|['"]$/g, ""))
    .filter(Boolean);
  if (entries.length === 0) return "none";
  return entries.every((e) => /(?:^|\.)AllowAny$/.test(e)) ? "allowAny" : "auth";
}

/** Replaces string literal contents so docstrings and messages do not count as code. */
function stripStrings(code: string): string {
  return code.replace(/("""|''')[\s\S]*?(?:\1|$)|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/g, '""');
}

function lastSegment(name: string): string {
  return name.split(".").pop() ?? name;
}

export class DjangoViewsDetector implements Detector {
  id = "django-views-detector";
  name = "Django View Auth Detection";
  category = "auth" as const;
  description =
    "Detects Django and Django REST Framework views that change data without an authentication check.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const viewFiles = context.files.filter(isViewFile);
    if (viewFiles.length === 0) return findings;

    const project = await this.projectAuth(context);

    for (const filePath of viewFiles) {
      let content: string;
      try {
        content = await context.readFile(filePath);
      } catch {
        continue;
      }
      if (!DJANGO_IMPORT_RE.test(content)) continue;

      for (const view of this.analyzeFile(content)) {
        const finding = this.judge(view, project, filePath);
        if (finding) findings.push(finding);
      }
    }
    return findings;
  }

  /** Project-wide auth that covers views without any decorator or mixin. */
  private async projectAuth(context: ScanContext): Promise<ProjectAuth> {
    const result: ProjectAuth = {
      drfDefaultProtected: false,
      loginRequiredMiddleware: false,
      wrapped: new Set(),
    };
    for (const filePath of context.files) {
      const normalized = filePath.replace(/\\/g, "/");
      const settings = isSettingsFile(normalized) && !isDevOnlySettings(normalized);
      const urls = /(^|\/)urls\.py$/.test(normalized);
      if (!settings && !urls) continue;
      let content: string;
      try {
        content = await context.readFile(filePath);
      } catch {
        continue;
      }
      const code = scanPythonLines(content)
        .filter((l) => !l.startsInString)
        .map((l) => l.code)
        .join("\n");

      if (settings) {
        const defaults = /['"]DEFAULT_PERMISSION_CLASSES['"]\s*:\s*([[(][^\])]*[\])])/.exec(code);
        if (defaults?.[1] && permissionKind(defaults[1]) === "auth") {
          result.drfDefaultProtected = true;
        }
        if (/\bLoginRequiredMiddleware\b/.test(code)) result.loginRequiredMiddleware = true;
      }
      if (urls) {
        const wrapper =
          /\b(?:\w+_required|user_passes_test\s*\([^)]*\)|permission_required\s*\([^)]*\))\s*\(\s*([\w.]+)/g;
        for (const m of code.matchAll(wrapper)) {
          const target = (m[1] ?? "").split(".").filter((s) => s !== "as_view");
          const name = target.pop();
          if (name) result.wrapped.add(name);
        }
      }
    }
    return result;
  }

  /** Top-level functions and classes, with their decorators and bodies. */
  private analyzeFile(content: string): ViewInfo[] {
    const statements = pythonStatements(scanPythonLines(content));
    const views: ViewInfo[] = [];
    const classes = new Map<string, ViewInfo>();
    let decorators: string[] = [];

    for (let i = 0; i < statements.length; i++) {
      const st = statements[i]!;
      if (st.indent !== 0) continue;
      if (st.head.trimStart().startsWith("@")) {
        decorators.push(st.stmt);
        continue;
      }
      const body: PythonStatement[] = [];
      for (let j = i + 1; j < statements.length && statements[j]!.indent > 0; j++) {
        body.push(statements[j]!);
      }

      const fn = /^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)/.exec(st.stmt);
      const cls = /^class\s+(\w+)\s*(?:\(([^)]*)\))?\s*:/.exec(st.stmt);
      if (fn) {
        views.push(this.functionView(fn[1]!, fn[2] ?? "", st, decorators, body));
      } else if (cls) {
        const info = this.classView(cls[1]!, cls[2] ?? "", st, decorators, body, classes);
        classes.set(info.name, info);
        views.push(info);
      }
      decorators = [];
    }
    return views;
  }

  private functionView(
    name: string,
    params: string,
    st: PythonStatement,
    decorators: string[],
    body: PythonStatement[],
  ): ViewInfo {
    const firstParam = (params.split(",")[0] ?? "").split(":")[0]!.trim();
    const decoText = decorators.join("\n");
    const bodyText = body.map((b) => b.stmt).join("\n");

    const apiView = /@\s*(?:[\w.]+\.)?api_view\b/.test(decoText);
    const permDeco = /@\s*(?:[\w.]+\.)?permission_classes\s*\(\s*([\s\S]*?)\)\s*$/m.exec(decoText);
    const permission = permDeco ? permissionKind(permDeco[1] ?? "") : undefined;
    const otherDecorators = decorators
      .filter((d) => !/@\s*(?:[\w.]+\.)?permission_classes\b/.test(d))
      .join("\n")
      .replace(/\blogin_not_required\b/g, "");

    const writes =
      /@\s*(?:[\w.]+\.)?require_POST\b/.test(decoText) ||
      (/\b(?:require_http_methods|api_view)\b/.test(decoText) && WRITE_METHOD_RE.test(decoText)) ||
      BODY_WRITE_RE.test(bodyText);

    return {
      name,
      line: st.start + 1,
      head: st.head,
      isView: firstParam === "request",
      isDrf: apiView,
      writes,
      auth:
        permission === "auth" ||
        AUTH_DECORATOR_RE.test(otherDecorators) ||
        BODY_AUTH_RE.test(stripStrings(bodyText)),
      permission,
      loginNotRequired: /\blogin_not_required\b/.test(decoText),
      unknownBase: false,
    };
  }

  private classView(
    name: string,
    basesText: string,
    st: PythonStatement,
    decorators: string[],
    body: PythonStatement[],
    classes: Map<string, ViewInfo>,
  ): ViewInfo {
    const bases = basesText
      .split(",")
      .map((b) => b.trim())
      .filter((b) => b && !b.includes("="))
      .map(lastSegment);

    const info: ViewInfo = {
      name,
      line: st.start + 1,
      head: st.head,
      isView: false,
      isDrf: false,
      writes: false,
      auth: false,
      permission: undefined,
      loginNotRequired: false,
      unknownBase: false,
    };

    for (const base of bases) {
      const parent = classes.get(base);
      if (parent) {
        info.isView ||= parent.isView;
        info.isDrf ||= parent.isDrf;
        info.writes ||= parent.writes;
        info.auth ||= parent.auth;
        info.permission ??= parent.permission;
        info.loginNotRequired ||= parent.loginNotRequired;
        info.unknownBase ||= parent.unknownBase;
      } else if (AUTH_MIXIN_RE.test(base)) {
        info.auth = true;
      } else if (DRF_VIEW_BASES.has(base)) {
        info.isView = true;
        info.isDrf = true;
        if (DRF_WRITE_BASES.has(base)) info.writes = true;
      } else if (DJANGO_VIEW_BASES.has(base)) {
        info.isView = true;
        if (DJANGO_WRITE_BASES.has(base)) info.writes = true;
      } else if (AUTH_BASE_NAME_RE.test(base)) {
        // A project base class such as AuthenticatedAPIView or StaffOnlyView.
        info.auth = true;
      } else if (!NEUTRAL_BASES.has(base) && !/Mixin$/.test(base)) {
        info.unknownBase = true;
      }
    }

    // Class decorators (@method_decorator(login_required, name="dispatch")) and the body.
    const decoText = decorators.join("\n");
    const innerDecorators = body
      .filter((b) => b.head.trimStart().startsWith("@"))
      .map((b) => b.stmt)
      .join("\n");
    const allDecorators = `${decoText}\n${innerDecorators}`;
    if (AUTH_DECORATOR_RE.test(allDecorators.replace(/\blogin_not_required\b/g, ""))) {
      info.auth = true;
    }
    if (/\blogin_not_required\b/.test(allDecorators)) info.loginNotRequired = true;

    let restrictedMethods: string | undefined;
    for (const b of body) {
      const perm = /^\s*permission_classes\s*[:=]\s*(?:[^=]*=)?\s*([\s\S]*)$/.exec(b.stmt);
      if (perm) info.permission = permissionKind(perm[1] ?? "");
      const authn = /^\s*authentication_classes\s*=\s*([\s\S]*)$/.exec(b.stmt);
      if (authn && permissionKind(authn[1] ?? "") === "auth") info.auth = true;
      const methods = /^\s*http_method_names\s*=\s*([\s\S]*)$/.exec(b.stmt);
      if (methods) restrictedMethods = methods[1] ?? "";
      if (/^\s*(?:async\s+)?def\s+(?:get_permissions|has_permission|test_func)\s*\(/.test(b.stmt)) {
        info.auth = true;
      }
      if (BODY_AUTH_RE.test(stripStrings(b.stmt))) info.auth = true;
      if (HTTP_HANDLER_RE.test(b.stmt)) info.isView = true;
      if (WRITE_HANDLER_RE.test(b.stmt)) info.writes = true;
      if (info.isDrf && VIEWSET_WRITE_ACTION_RE.test(b.stmt)) info.writes = true;
      if (/^\s*@\s*(?:[\w.]+\.)?action\s*\(/.test(b.stmt) && WRITE_METHOD_RE.test(b.stmt)) {
        info.writes = true;
      }
    }
    if (info.permission === "auth") info.auth = true;
    // http_method_names = ["get", "head"] turns every write handler off.
    if (
      restrictedMethods !== undefined &&
      !/['"](?:post|put|patch|delete)['"]/i.test(restrictedMethods)
    ) {
      info.writes = false;
    }
    return info;
  }

  private judge(view: ViewInfo, project: ProjectAuth, filePath: string): Finding | null {
    if (!view.isView || !view.writes || view.auth) return null;
    if (isPublicViewName(view.name)) return null;

    if (view.permission === "allowAny") {
      return this.finding(ALLOW_ANY_RULE, view, filePath);
    }
    if (project.wrapped.has(view.name)) return null;
    // An explicit empty permission_classes opts out of the project default.
    if (view.isDrf && view.permission === undefined && project.drfDefaultProtected) return null;
    if (!view.isDrf && project.loginRequiredMiddleware && !view.loginNotRequired) return null;
    return this.finding(MISSING_AUTH_RULE, view, filePath);
  }

  private finding(ruleId: string, view: ViewInfo, filePath: string): Finding {
    const allowAny = ruleId === ALLOW_ANY_RULE;
    const kind = view.isDrf ? "Django REST Framework view" : "Django view";
    return {
      id: createFindingId(CATEGORY_PREFIX.auth, ruleId, filePath, view.line, view.name),
      ruleId,
      title: allowAny
        ? `DRF view ${view.name} lets anyone change data`
        : `${kind} ${view.name} changes data without authentication`,
      severity: allowAny ? "medium" : "high",
      category: "auth",
      deployBlocking: false,
      confidence: view.unknownBase ? "low" : "medium",
      file: filePath,
      line: view.line,
      evidence: sanitizeEvidence(view.head.trim()),
      plainEnglishProblem: allowAny
        ? `The ${kind} ${view.name} accepts POST/PUT/PATCH/DELETE requests and its permission_classes is AllowAny, so anyone can call it without logging in.`
        : `The ${kind} ${view.name} accepts POST/PUT/PATCH/DELETE requests, but we couldn't find a login or permission check (no @login_required, LoginRequiredMixin, or DRF permission_classes).`,
      whyItMatters:
        "Anyone on the internet can call this endpoint directly and create, change or delete data without an account.",
      fixSteps: view.isDrf
        ? [
            allowAny
              ? "Replace AllowAny with IsAuthenticated (or a stricter permission) on this view."
              : "Add permission_classes = [IsAuthenticated] (or a stricter permission) to this view.",
            'Or protect every API view by default: REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}.',
            "Keep AllowAny only for endpoints that must be public, such as sign up or login.",
          ]
        : [
            "Add @login_required to this function view, or LoginRequiredMixin as the first base class of this class-based view.",
            "Use @permission_required / PermissionRequiredMixin when only some users may change this data.",
          ],
      autoFixAvailable: false,
      aiFixPrompt: view.isDrf
        ? `My Django REST Framework view ${view.name} changes data but anyone can call it. Please add an authentication/permission check (IsAuthenticated or a stricter permission class) and keep any truly public endpoints explicit.`
        : `My Django view ${view.name} changes data without checking who the user is. Please protect it with @login_required or LoginRequiredMixin (and a permission check if only some users may do this).`,
    };
  }
}
