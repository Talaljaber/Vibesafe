/** Minimal `vscode` module mock for unit tests. */
export class MarkdownString {
  value = "";
  isTrusted: boolean | { enabledCommands: string[] } | undefined;
  supportHtml: boolean | undefined;
  appendMarkdown(s: string): this {
    this.value += s;
    return this;
  }
}

export class Hover {
  constructor(public contents: MarkdownString) {}
}

export class Range {
  constructor(
    public startLine: number,
    public startChar: number,
    public endLine: number,
    public endChar: number,
  ) {}
}

export class Position {
  constructor(
    public line: number,
    public character: number,
  ) {}
}

export const Uri = {
  file: (p: string) => ({ fsPath: p }),
};
