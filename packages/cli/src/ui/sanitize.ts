/**
 * Strips ANSI/OSC escape sequences and C0/C1 control characters (keeping \n and \t) from text that
 * originates in the scanned repo, so it cannot rewrite or hide parts of the terminal output.
 */
export function sanitizeTerminal(text: string): string {
  return text
    .replace(/\u001b\[[0-?]*[ -\/]*[@-~]/g, "")
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g, "")
    .replace(/\u001b[@-_]?/g, "")
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/g, "");
}
