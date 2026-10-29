import { describe, it, expect } from "vitest";
import {
  SINK_PATTERNS,
  normalizeModuleName,
  sinkPatternsOf,
} from "../../src/detectors/patterns/sink-patterns.js";
import { createJsSource } from "../../src/detectors/utils/js-source.js";
import {
  findSinkCalls,
  resolveCallAliases,
  staticText,
  taintPosition,
} from "../../src/detectors/utils/sinks.js";

const src = (text: string) => createJsSource(text, { jsx: false });
const callees = (text: string, kinds = sinkPatternsOf("command", "path", "redirect", "ssrf")) => {
  const s = src(text);
  return findSinkCalls(s, kinds, resolveCallAliases(s)).map((c) => c.callee);
};

describe("sink patterns", () => {
  it("have unique ids", () => {
    const ids = SINK_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("normalises module names", () => {
    expect(normalizeModuleName("node:child_process")).toBe("child_process");
    expect(normalizeModuleName("fs/promises")).toBe("fs");
    expect(normalizeModuleName("fs-extra")).toBe("fs");
    expect(normalizeModuleName("node-fetch")).toBe("fetch");
    expect(normalizeModuleName("@/lib/db")).toBe("@/lib/db");
  });
});

describe("resolveCallAliases", () => {
  it("resolves named, renamed, namespace and default imports of known modules", () => {
    const aliases = resolveCallAliases(
      src(`import { exec as sh, spawn } from "node:child_process";
import * as cp from "child_process";
import fs from "fs/promises";
import { readFile } from "fs/promises";
import { NextResponse } from "next/server";
import axios from "axios";`),
    );
    expect(aliases.get("sh")).toBe("child_process.exec");
    expect(aliases.get("spawn")).toBe("child_process.spawn");
    expect(aliases.get("cp")).toBe("child_process");
    expect(aliases.get("fs")).toBe("fs");
    expect(aliases.get("readFile")).toBe("fs.readFile");
    expect(aliases.get("NextResponse")).toBe("next/server.NextResponse");
    expect(aliases.get("axios")).toBe("axios");
  });

  it("resolves require destructuring and promisify(exec)", () => {
    const aliases = resolveCallAliases(
      src(`const { exec } = require("child_process");
const { promisify } = require("util");
const run = promisify(exec);
const { readFile: rf } = require("fs").promises;
const execP = util.promisify(require("child_process").exec);`),
    );
    expect(aliases.get("exec")).toBe("child_process.exec");
    expect(aliases.get("run")).toBe("child_process.exec");
    expect(aliases.get("rf")).toBe("fs.promises.readFile");
    expect(aliases.get("execP")).toBe("child_process.exec");
  });

  it("never resolves project modules or type-only imports", () => {
    const aliases = resolveCallAliases(
      src(`import { exec } from "@/lib/shell";
import type { Stats } from "fs";
import { run } from "./run";`),
    );
    expect(aliases.has("exec")).toBe(false);
    expect(aliases.has("Stats")).toBe(false);
    expect(aliases.has("run")).toBe(false);
  });
});

describe("findSinkCalls", () => {
  it("finds aliased and inline-require sinks", () => {
    expect(
      callees(`import { exec as sh } from "child_process";
sh("ls");
require("child_process").execSync("pwd");
const fs = require("fs");
fs.promises.readFile(p);`),
    ).toEqual(["child_process.exec", "child_process.execSync", "fs.readFile"]);
  });

  it("skips declarations, method definitions, comments and strings", () => {
    expect(
      callees(`import { exec } from "child_process";
// exec("rm -rf /")
const s = "exec(x)";
function exec2() {}
class Runner { async exec(cmd) { return cmd; } }`),
    ).toEqual([]);
  });

  it("does not treat a local helper named exec as child_process.exec", () => {
    expect(callees(`import { exec } from "@/lib/shell";\nexec(cmd);`)).toEqual([]);
  });

  it("matches constructor-only and call-only patterns correctly", () => {
    const evalPatterns = sinkPatternsOf("eval");
    const s = src(`import vm from "vm";
new vm.Script(code);
vm.Script(code);
new Function("a", body);
eval(x);
redis.eval(script);
page.evaluate(fn);`);
    expect(findSinkCalls(s, evalPatterns, resolveCallAliases(s)).map((c) => c.callee)).toEqual([
      "vm.Script",
      "Function",
      "eval",
    ]);
  });

  it("reads static SQL text of template and string arguments", () => {
    const s = src("db.query(`SELECT * FROM t WHERE a = '${x}'` + \" AND b = 1\")");
    const [call] = findSinkCalls(s, sinkPatternsOf("sql"), new Map());
    expect(call).toBeDefined();
    expect(staticText(s, call!.args[0]!)).toContain("SELECT * FROM t WHERE a = ' X '");
  });
});

describe("taintPosition", () => {
  it("places taint relative to a static prefix", () => {
    expect(taintPosition("")).toBe("whole");
    expect(taintPosition("https://")).toBe("url-origin");
    expect(taintPosition("X")).toBe("url-origin");
    expect(taintPosition("/")).toBe("url-origin");
    expect(taintPosition("https://api.example.com/users/")).toBe("url-path");
    expect(taintPosition("X/items/")).toBe("url-path");
    expect(taintPosition("https://api.example.com/search?q=")).toBe("inner");
    expect(taintPosition("https://api.example.com/", "url-origin")).toBe("url-path");
  });
});
