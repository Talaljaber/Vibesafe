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

function exportRes(method: string): RegExp[] {
  return [
    new RegExp(`^\\s*export\\s+(?:async\\s+)?function\\s*\\*?\\s*${method}\\b`),
    new RegExp(`^\\s*export\\s+(?:const|let|var)\\s+${method}\\b`),
    new RegExp(`^\\s*export\\s*\\{[^}]*\\b${method}\\b[^}]*\\}`),
  ];
}

/**
 * Export line of every handler in the file, sorted by line. Only real `export` forms count as
 * boundaries (a quoted "POST" string in a GET body must not cut the GET span).
 */
export function handlerLines(content: string): { method: string; line: number }[] {
  const lines = content.split(/\r?\n/);
  const out: { method: string; line: number }[] = [];
  for (const method of HANDLER_METHODS) {
    const res = exportRes(method);
    const idx = lines.findIndex((l) => res.some((re) => re.test(l)));
    if (idx >= 0) out.push({ method, line: idx + 1 });
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
 * `line`. Undefined when no handler starts at or before it. When several methods share one
 * export line (`export { h as GET, h as POST }`) the last in HANDLER_METHODS order wins, i.e. a
 * non-GET method (the safe direction: the planner will not treat it as a readable GET).
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
