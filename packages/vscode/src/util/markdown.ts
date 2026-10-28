/**
 * Escape text so it renders literally inside a VS Code MarkdownString.
 * Finding text can include content from the scanned repository, so it must
 * never be interpreted as Markdown, links, or HTML.
 */
export function escapeMarkdown(text: string): string {
  return String(text)
    .replace(/[\\`*_{}[\]()<>#+\-.!|~&:@]/g, "\\$&")
    .replace(/\r?\n/g, " ");
}

/** The only commands hover markdown is allowed to invoke. */
export const TRUSTED_COMMANDS = ["vibesafe.copyFixPrompt", "vibesafe.applyFix"];

/** Build a command URI that carries only a finding id. */
export function findingCommandUri(command: string, findingId: string): string {
  return `command:${command}?${encodeURIComponent(JSON.stringify([findingId]))}`;
}
