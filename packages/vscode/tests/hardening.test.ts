import { describe, it, expect } from "vitest";
import { escapeMarkdown, findingCommandUri } from "../src/util/markdown.js";
import {
  resolveFindingId,
  findFindingById,
  isInsideRoot,
  isFindingInsideRoot,
} from "../src/util/findings.js";
import type { Finding, ScanResult } from "@talaljaber/vibesafe-shared";

const mk = (id: string, file?: string): Finding => ({ id, file }) as unknown as Finding;

describe("escapeMarkdown", () => {
  it("escapes links, html and command syntax", () => {
    const out = escapeMarkdown("[x](command:vibesafe.applyFix) <img src=x onerror=1> `a`");
    expect(out).not.toMatch(/(^|[^\\])\[/);
    expect(out).not.toMatch(/(^|[^\\])</);
    expect(out).not.toMatch(/(^|[^\\])`/);
    expect(out).toContain("\\[x\\]\\(command\\:");
  });
  it("flattens newlines", () => {
    expect(escapeMarkdown("a\nb\r\nc")).toBe("a b c");
  });
});

describe("findingCommandUri", () => {
  it("carries only the id", () => {
    const uri = findingCommandUri("vibesafe.applyFix", "abc");
    expect(uri.startsWith("command:vibesafe.applyFix?")).toBe(true);
    expect(JSON.parse(decodeURIComponent(uri.split("?")[1]!))).toEqual(["abc"]);
  });
});

describe("resolveFindingId / findFindingById", () => {
  const result = { findings: [mk("a"), mk("b")] } as unknown as ScanResult;
  it("accepts string, array and tree element", () => {
    expect(resolveFindingId("a")).toBe("a");
    expect(resolveFindingId(["b"])).toBe("b");
    expect(resolveFindingId({ finding: { id: "a" } })).toBe("a");
    expect(resolveFindingId(42)).toBeUndefined();
  });
  it("looks up in the scan result, ignoring argument content", () => {
    expect(findFindingById(result, "b")?.id).toBe("b");
    expect(findFindingById(result, "zzz")).toBeUndefined();
    expect(findFindingById(null, "a")).toBeUndefined();
  });
});

describe("path containment", () => {
  it("rejects paths outside the root", () => {
    expect(isInsideRoot("/ws/proj", "/ws/proj/src/a.ts")).toBe(true);
    expect(isInsideRoot("/ws/proj", "/ws/other/a.ts")).toBe(false);
    expect(isFindingInsideRoot("/ws/proj", mk("x", "../../etc/passwd"))).toBe(false);
    expect(isFindingInsideRoot("/ws/proj", mk("x", "src/a.ts"))).toBe(true);
    expect(isFindingInsideRoot("/ws/proj", mk("x"))).toBe(true);
  });
});
