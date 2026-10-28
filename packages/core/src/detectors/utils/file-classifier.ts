/**
 * Strips leading whitespace, `//` line comments and block comments so the first
 * real statement of a file can be inspected.
 */
function stripLeadingComments(content: string): string {
  let rest = content.replace(/^﻿/, "");
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

/**
 * Determines if a file is explicitly marked for the client-side
 * or typically exposed to the client in Next.js.
 */
export function isClientFile(filePath: string, fileContent: string): boolean {
  // Next.js "use client" directive must be the first statement
  if (hasUseClientDirective(fileContent)) {
    return true;
  }

  // Next.js Pages router: files in pages/ or src/pages/ (except pages/api) are client-accessible
  const normalizedPath = filePath.replace(/\\/g, "/");
  if (
    /(^|\/)(src\/)?pages\//.test(normalizedPath) &&
    !/(^|\/)(src\/)?pages\/api\//.test(normalizedPath)
  ) {
    return true;
  }

  return false;
}
