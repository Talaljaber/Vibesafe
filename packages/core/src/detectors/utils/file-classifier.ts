import path from "path";

/**
 * Determines if a file is explicitly marked for the client-side
 * or typically exposed to the client in Next.js.
 */
export function isClientFile(filePath: string, fileContent: string): boolean {
  // Check for Next.js "use client" directive
  if (fileContent.includes('"use client"') || fileContent.includes("'use client'")) {
    return true;
  }

  // Next.js Pages router: files in pages/ (except pages/api) are client-accessible by default
  const normalizedPath = filePath.replace(/\\/g, "/");
  if (normalizedPath.startsWith("pages/") && !normalizedPath.startsWith("pages/api/")) {
    return true;
  }

  // Next.js App router: layout and page are server components by default unless marked "use client"
  // However, components/ or ui/ might be client components. 
  // For strict detection, "use client" is the main heuristic for App Router.

  return false;
}

export function isServerFile(filePath: string, fileContent: string): boolean {
  if (fileContent.includes('"use server"') || fileContent.includes("'use server'")) {
    return true;
  }

  const normalizedPath = filePath.replace(/\\/g, "/");
  if (normalizedPath.startsWith("app/api/") || normalizedPath.startsWith("pages/api/")) {
    return true;
  }

  return false;
}
