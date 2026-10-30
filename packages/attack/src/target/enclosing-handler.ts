import { findHandlerLine } from "@talaljaber/vibesafe-core";

/** HTTP methods a route file can export a handler for. */
export const HANDLER_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;

export interface HandlerSpan {
  method: string;
  /** 1-indexed line of the handler's export. */
  startLine: number;
  /** 1-indexed inclusive last line: up to the next handler export, or end of file. */
  endLine: number;
  /** Source text of the span. */
  body: string;
}

/** Export line of every handler in the file, sorted by line. */
function handlerLines(content: string): { method: string; line: number }[] {
  const out: { method: string; line: number }[] = [];
  for (const method of HANDLER_METHODS) {
    const line = findHandlerLine(content, [method]);
    if (line !== undefined) out.push({ method, line });
  }
  return out.sort((a, b) => a.line - b.line);
}

function spanOf(content: string, handlers: { method: string; line: number }[], idx: number) {
  const lines = content.split(/\r?\n/);
  const cur = handlers[idx]!;
  const next = handlers.slice(idx + 1).find((h) => h.line > cur.line);
  const endLine = next ? next.line - 1 : lines.length;
  return {
    method: cur.method,
    startLine: cur.line,
    endLine,
    body: lines.slice(cur.line - 1, endLine).join("\n"),
  } satisfies HandlerSpan;
}

/**
 * The handler enclosing `line`: the method whose export line is the largest value at or before
 * `line`. Undefined when no handler starts at or before it.
 */
export function enclosingHandler(content: string, line: number): HandlerSpan | undefined {
  const handlers = handlerLines(content);
  let idx = -1;
  handlers.forEach((h, i) => {
    if (h.line <= line) idx = i;
  });
  return idx < 0 ? undefined : spanOf(content, handlers, idx);
}

/** The span of the handler for one method, or undefined when the file does not export it. */
export function handlerSpan(content: string, method: string): HandlerSpan | undefined {
  const handlers = handlerLines(content);
  const idx = handlers.findIndex((h) => h.method === method);
  return idx < 0 ? undefined : spanOf(content, handlers, idx);
}
