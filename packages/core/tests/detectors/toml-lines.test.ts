import { describe, it, expect } from "vitest";
import { scanTomlLines, tomlGet } from "../../src/detectors/utils/toml-lines.js";

describe("scanTomlLines", () => {
  it("parses tables, bools, ints and strings with comments", () => {
    const { entries, tables } = scanTomlLines(
      [
        "top = 1",
        "[auth] # header comment",
        "enabled = true",
        "jwt_expiry = 1_000",
        'site_url = "http://x.test/#frag" # trailing',
        "name = 'lit'",
        "[[auth.hook]]",
        'uri = "pg-functions://a"',
      ].join("\n"),
    );
    expect(tables.get("auth")).toBe(2);
    expect(tables.has("auth.hook")).toBe(true);
    expect(tomlGet(entries, "", "top")?.value).toEqual({ kind: "int", value: 1 });
    expect(tomlGet(entries, "auth", "enabled")?.value).toEqual({ kind: "bool", value: true });
    expect(tomlGet(entries, "auth", "jwt_expiry")?.value).toEqual({ kind: "int", value: 1000 });
    expect(tomlGet(entries, "auth", "site_url")?.value).toEqual({
      kind: "string",
      value: "http://x.test/#frag",
    });
    expect(tomlGet(entries, "auth", "name")?.value).toEqual({ kind: "string", value: "lit" });
    expect(tomlGet(entries, "auth.hook", "uri")?.line).toBe(8);
  });

  it("reads single-line and multi-line string arrays", () => {
    const { entries } = scanTomlLines(
      [
        "[auth]",
        "a = [\"x\", 'y']",
        "b = [",
        '  "one", # c',
        '  "two",',
        "]",
        "c = []",
        "d = true",
      ].join("\n"),
    );
    expect(tomlGet(entries, "auth", "a")?.value).toEqual({
      kind: "string-array",
      values: ["x", "y"],
    });
    expect(tomlGet(entries, "auth", "b")?.value).toEqual({
      kind: "string-array",
      values: ["one", "two"],
    });
    expect(tomlGet(entries, "auth", "c")?.value).toEqual({ kind: "string-array", values: [] });
    expect(tomlGet(entries, "auth", "d")?.line).toBe(8);
  });

  it("treats mixed arrays and inline tables as other", () => {
    const { entries } = scanTomlLines(
      ["[a]", 'm = ["x", 1]', 'n = [["x"]]', 'o = { k = "v" }', "p = 3"].join("\n"),
    );
    expect(tomlGet(entries, "a", "m")?.value.kind).toBe("other");
    expect(tomlGet(entries, "a", "n")?.value.kind).toBe("other");
    expect(tomlGet(entries, "a", "o")?.value.kind).toBe("other");
    expect(tomlGet(entries, "a", "p")?.value).toEqual({ kind: "int", value: 3 });
  });

  it("bounds an unterminated array to 200 lines", () => {
    const lines = ["[a]", "big = ["];
    for (let i = 0; i < 300; i++) lines.push(`  "v${i}",`);
    lines.push("after = 1");
    const { entries } = scanTomlLines(lines.join("\n"));
    expect(tomlGet(entries, "a", "big")?.value.kind).toBe("other");
    expect(tomlGet(entries, "a", "after")?.value).toEqual({ kind: "int", value: 1 });
  });

  it("last duplicate wins and malformed input does not throw", () => {
    const { entries } = scanTomlLines('[a]\nk = 1\nk = 2\ns = "unterminated\n=\n[\n');
    expect(tomlGet(entries, "a", "k")?.value).toEqual({ kind: "int", value: 2 });
    expect(tomlGet(entries, "a", "s")?.value.kind).toBe("other");
  });
});
