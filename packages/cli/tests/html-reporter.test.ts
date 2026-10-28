import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { writeReportSafely } from "../src/ui/html-reporter.js";

const dirs: string[] = [];
function tmp(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-report-"));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe("writeReportSafely", () => {
  it("creates the report and leaves no temp files", async () => {
    const dir = tmp();
    const target = path.join(dir, "vibesafe-report.html");
    await writeReportSafely(target, "<html>1</html>");
    expect(fs.readFileSync(target, "utf-8")).toBe("<html>1</html>");
    expect(fs.readdirSync(dir)).toEqual(["vibesafe-report.html"]);
  });

  it("replaces an existing regular file", async () => {
    const dir = tmp();
    const target = path.join(dir, "vibesafe-report.html");
    fs.writeFileSync(target, "old");
    await writeReportSafely(target, "new");
    expect(fs.readFileSync(target, "utf-8")).toBe("new");
  });

  it("refuses to write through a symlink and leaves the link target untouched", async () => {
    const dir = tmp();
    const victim = path.join(dir, "victim.txt");
    fs.writeFileSync(victim, "keep");
    const target = path.join(dir, "vibesafe-report.html");
    try {
      fs.symlinkSync(victim, target);
    } catch {
      return; // symlinks not permitted on this machine
    }
    await expect(writeReportSafely(target, "pwned")).rejects.toThrow(/symbolic link/);
    expect(fs.readFileSync(victim, "utf-8")).toBe("keep");
  });
});
