import type { ProjectContext } from "@talaljaber/vibesafe-shared";

/**
 * Strips leading whitespace, `//` line comments and block comments so the first
 * real statement of a file can be inspected.
 */
function stripLeadingComments(content: string): string {
  let rest = content.replace(/^\uFEFF/, "");
  for (;;) {
    const trimmed = rest.replace(/^\s+/, "");
    if (trimmed.startsWith("//")) {
      const nl = trimmed.indexOf("\n");
      rest = nl === -1 ? "" : trimmed.slice(nl + 1);
    } else if (trimmed.startsWith("/*")) {
      const end = trimmed.indexOf("*/");
      rest = end === -1 ? "" : trimmed.slice(end + 2);
    } else {
      return trimmed;
    }
  }
}

/** True when the file starts with a `"use client"` directive (after comments/blank lines). */
export function hasUseClientDirective(fileContent: string): boolean {
  return /^(["'])use client\1/.test(stripLeadingComments(fileContent));
}

/** True for `vite.config.{ts,mts,js,mjs,cjs}` (any directory). */
export function isViteConfigFile(filePath: string): boolean {
  return /(^|\/)vite\.config\.(ts|mts|js|mjs|cjs)$/.test(filePath.replace(/\\/g, "/"));
}

/**
 * In a Vite project everything under `src/` is bundled for the browser, except the
 * Vite config itself, tests/mocks/e2e and files that are clearly server-side (`server/`, `api/`,
 * `*.server.*`, `entry-server.*`). Fullstack Vite + Express layouts are best-effort.
 */
function isViteClientPath(normalizedPath: string): boolean {
  if (!/(^|\/)src\//.test(normalizedPath)) return false;
  if (!/\.(ts|tsx|js|jsx)$/.test(normalizedPath)) return false;
  if (isViteConfigFile(normalizedPath)) return false;
  if (/(^|\/)(server|api)\//.test(normalizedPath)) return false;
  // Tests, mocks, e2e suites and SSR entries are never bundled for the browser.
  if (/\.(test|spec)\.[^/]+$/.test(normalizedPath)) return false;
  if (/(^|\/)(__tests__|__mocks__|e2e)\//.test(normalizedPath)) return false;
  if (/(^|\/)entry-server\.[^/]+$/.test(normalizedPath)) return false;
  if (/\.server\.[^/]+$/.test(normalizedPath)) return false;
  return true;
}

/** True when the file starts with a `"use server"` directive (after comments/blank lines). */
export function hasUseServerDirective(fileContent: string): boolean {
  return /^(["'])use server\1/.test(stripLeadingComments(fileContent));
}

/**
 * True for a Pages-router file (outside pages/api) that exports getServerSideProps, getStaticProps or
 * getInitialProps. Next.js tree-shakes server-only imports used by these out of the client bundle, so
 * top-level imports such as firebase-admin there are not treated as client exposure (tradeoff: a
 * client-side use in the same file is not reported).
 */
export function usesServerSideDataFetching(filePath: string, fileContent: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  if (!/(^|\/)(src\/)?pages\//.test(p) || /(^|\/)(src\/)?pages\/api\//.test(p)) return false;
  return /\bexport\s+(?:async\s+)?(?:function|const|let|var)\s+(?:getServerSideProps|getStaticProps|getInitialProps)\b|\bexport\s*\{[^}]*\b(?:getServerSideProps|getStaticProps)\b|\.getInitialProps\s*=/.test(
    fileContent,
  );
}

/**
 * Determines if a file is explicitly marked for the client-side
 * or typically exposed to the client (Next.js conventions, or any `src/` code in a Vite project).
 */
export function isClientFile(
  filePath: string,
  fileContent: string,
  projectContext?: Pick<ProjectContext, "framework">,
): boolean {
  // A leading "use server" directive marks Server Actions: never bundled as client code
  if (hasUseServerDirective(fileContent)) {
    return false;
  }

  // Next.js "use client" directive must be the first statement
  if (hasUseClientDirective(fileContent)) {
    return true;
  }

  const normalizedPath = filePath.replace(/\\/g, "/");

  // Next.js Pages router: files in pages/ or src/pages/ (except pages/api) are client-accessible
  if (
    /(^|\/)(src\/)?pages\//.test(normalizedPath) &&
    !/(^|\/)(src\/)?pages\/api\//.test(normalizedPath)
  ) {
    return true;
  }

  if (projectContext?.framework === "vite" && isViteClientPath(normalizedPath)) {
    return true;
  }

  return false;
}
