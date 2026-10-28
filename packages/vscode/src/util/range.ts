/**
 * Compute the [startLine, startChar, endLine, endChar] of a diagnostic range
 * for a 1-based finding line. When the document is open, `lineText` gives the
 * real line; otherwise the range extends to the end of the line.
 */
export function diagnosticRangeCoords(
  line1Based: number,
  lineText?: string,
): [number, number, number, number] {
  const line = Math.max(0, line1Based - 1);
  const start = lineText === undefined ? 0 : lineText.length - lineText.trimStart().length;
  const end = lineText === undefined ? Number.MAX_SAFE_INTEGER : lineText.length;
  return [line, Math.min(start, end), line, end];
}
