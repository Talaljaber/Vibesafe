import { describe, it, expect } from "vitest";
import {
  classifyCondition,
  classifyRtdbValue,
  collectRuleFunctions,
  isSensitiveName,
  maskRulesSource,
  nameSensitivity,
  parseDatabaseRules,
  parseRulesFile,
  stripRulesComments,
} from "../../src/detectors/utils/firebase-rules.js";

const NOW = Date.UTC(2026, 9, 30);
const NO_FNS = new Map<string, string | null>();
const cls = (cond: string | undefined, fns = NO_FNS): string =>
  classifyCondition(cond, fns, NOW).cls;

describe("nameSensitivity", () => {
  it("separates directory, private and unknown names", () => {
    expect(nameSensitivity("users")).toBe("directory");
    expect(nameSensitivity("Profile")).toBe("directory");
    expect(nameSensitivity("orders")).toBe("private");
    expect(nameSensitivity("Invoice")).toBe("private");
    expect(nameSensitivity("auditEvents")).toBe("private");
    expect(nameSensitivity("posts")).toBeNull();
    expect(nameSensitivity("public")).toBeNull();
    expect(isSensitiveName("payments")).toBe(true);
    expect(isSensitiveName("catalog")).toBe(false);
  });
});

describe("maskRulesSource / stripRulesComments", () => {
  const text = "a // c1\n/* b\nc */ 'str//x' \"q\" d";
  it("keeps length and newlines", () => {
    expect(maskRulesSource(text)).toHaveLength(text.length);
    expect(stripRulesComments(text)).toHaveLength(text.length);
    expect(maskRulesSource(text).split("\n")).toHaveLength(3);
  });
  it("blanks comments and string contents; strip keeps strings", () => {
    const masked = maskRulesSource(text);
    expect(masked).not.toContain("c1");
    expect(masked).not.toContain("str");
    expect(masked).toContain("a");
    expect(stripRulesComments(text)).toContain("'str//x'");
    expect(stripRulesComments(text)).not.toContain("c1");
  });
});

describe("parseRulesFile", () => {
  it("concatenates nested match paths and strips the firestore prefix", () => {
    const stmts = parseRulesFile(
      [
        "rules_version = '2';",
        "service cloud.firestore {",
        "  match /databases/{database}/documents {",
        "    match /teams/{teamId} {",
        "      match /projects/{projectId} {",
        "        allow read: if request.auth != null;",
        "      }",
        "    }",
        "    match /posts/{id} { allow get, list; }",
        "  }",
        "}",
      ].join("\n"),
    );
    expect(stmts.map((s) => s.segments)).toEqual([
      ["teams", "{teamId}", "projects", "{projectId}"],
      ["posts", "{id}"],
    ]);
    expect(stmts[0]).toMatchObject({
      service: "firestore",
      methods: ["read"],
      line: 6,
      endLine: 6,
    });
    expect(stmts[0]?.condition).toBe("request.auth != null");
    expect(stmts[1]).toMatchObject({ methods: ["get", "list"], condition: undefined });
  });

  it("strips the storage prefix and handles multi-line statements", () => {
    const stmts = parseRulesFile(
      [
        "service firebase.storage {",
        "  match /b/{bucket}/o {",
        "    match /{allPaths=**} {",
        "      allow write:",
        "        if request.auth != null",
        "        && request.resource.size < 1024;",
        "    }",
        "  }",
        "}",
      ].join("\n"),
    );
    expect(stmts).toHaveLength(1);
    expect(stmts[0]).toMatchObject({
      service: "storage",
      segments: ["{allPaths=**}"],
      line: 4,
      endLine: 6,
    });
  });

  it("returns [] without a service header, ignores comments and never throws", () => {
    expect(parseRulesFile("allow read: if true;")).toEqual([]);
    expect(parseRulesFile("")).toEqual([]);
    expect(
      parseRulesFile("service cloud.firestore { match /a/{b} { // allow read: if true;\n } }"),
    ).toEqual([]);
    expect(parseRulesFile("service cloud.firestore { match /a/{b {{{ allow read")).toEqual([]);
  });

  it("does not treat function bodies as statements", () => {
    const stmts = parseRulesFile(
      "service cloud.firestore { function f() { return true; } match /a/{b} { allow read: if f(); } }",
    );
    expect(stmts).toHaveLength(1);
    expect(stmts[0]?.condition).toBe("f()");
  });
});

describe("collectRuleFunctions", () => {
  it("collects single-return functions and marks others opaque", () => {
    const text = [
      "service cloud.firestore {",
      "  function signedIn() { return request.auth != null; }",
      "  function owner(uid) { return signedIn() && request.auth.uid == uid; }",
      "  function complex(x) { let y = x; return y == 1; }",
      "}",
    ].join("\n");
    const fns = collectRuleFunctions(maskRulesSource(text), stripRulesComments(text));
    expect(fns.get("signedIn")).toBe("request.auth != null");
    expect(fns.get("owner")).toBe("signedIn() && request.auth.uid == uid");
    expect(fns.get("complex")).toBeNull();
  });
});

describe("classifyCondition truth table", () => {
  it("handles literal and missing conditions", () => {
    expect(cls(undefined)).toBe("open");
    expect(cls("true")).toBe("open");
    expect(cls("false")).toBe("deny");
  });
  it("classifies test-mode atoms and expired ones", () => {
    expect(classifyCondition("request.time < timestamp.date(2099, 1, 1)", NO_FNS, NOW)).toEqual({
      cls: "test-mode",
      expiresAt: Date.UTC(2099, 0, 1),
    });
    expect(cls("timestamp.date(2099, 1, 1) >= request.time")).toBe("test-mode");
    expect(cls("request.time <= timestamp.value(4102444800000)")).toBe("test-mode");
    expect(cls("request.time < timestamp.date(2020, 1, 1)")).toBe("deny");
  });
  it("classifies signed-in atoms", () => {
    for (const c of [
      "request.auth != null",
      "null != request.auth",
      "request.auth.uid != null",
      "request.auth.token.email_verified == true",
      "request.auth.token.email_verified",
      "request.auth.token.firebase.sign_in_provider != 'anonymous'",
    ]) {
      expect(cls(c), c).toBe("signed-in");
    }
  });
  it("treats owner checks, claims and lookups as scoped", () => {
    for (const c of [
      "request.auth.uid == userId",
      "resource.data.ownerId == request.auth.uid",
      "request.auth.token.admin == true",
      "exists(/databases/$(database)/documents/admins/$(request.auth.uid))",
      "!(request.auth == null)",
    ]) {
      expect(cls(c), c).toBe("scoped");
    }
  });
  it("combines && by the least permissive and || by the most permissive", () => {
    expect(cls("request.auth != null && request.auth.uid == uid")).toBe("scoped");
    expect(cls("request.auth != null && request.resource.data.title is string")).toBe("signed-in");
    expect(cls("request.resource.data.title is string")).toBe("open");
    expect(cls("request.auth.uid == uid || true")).toBe("open");
    expect(cls("request.auth.uid == uid || request.auth != null")).toBe("signed-in");
    expect(cls("(request.auth != null) && (request.auth.uid == uid || false)")).toBe("scoped");
    expect(cls("request.resource.data.ownerId == request.auth.uid")).toBe("scoped");
  });
  it("inlines functions up to three rounds and treats opaque bodies as scoped", () => {
    const fns = new Map<string, string | null>([
      ["a", "request.auth != null"],
      ["b", "a()"],
      ["c", "b()"],
      ["d", "c()"],
      ["e", "d()"],
      ["opaque", null],
    ]);
    expect(cls("a()", fns)).toBe("signed-in");
    expect(cls("c()", fns)).toBe("signed-in");
    expect(cls("e()", fns)).toBe("scoped");
    expect(cls("opaque()", fns)).toBe("scoped");
    expect(cls("signedIn()")).toBe("scoped");
  });
});

describe("parseDatabaseRules / classifyRtdbValue", () => {
  it("reports line numbers and paths, ignoring comments", () => {
    const rules = parseDatabaseRules(
      [
        "{",
        "  // top",
        '  "rules": {',
        '    ".read": true, /* c */',
        '    "users": {',
        '      "$uid": {',
        '        ".read": "$uid === auth.uid",',
        '        ".indexOn": ["a", "b"],',
        '        ".write": "auth != null"',
        "      }",
        "    }",
        "  }",
        "}",
      ].join("\n"),
    );
    expect(rules).toEqual([
      { path: [], key: ".read", value: true, line: 4 },
      { path: ["users", "$uid"], key: ".read", value: "$uid === auth.uid", line: 7 },
      { path: ["users", "$uid"], key: ".write", value: "auth != null", line: 9 },
    ]);
  });
  it("never throws on malformed input", () => {
    expect(() => parseDatabaseRules('{"rules": {".read": ')).not.toThrow();
    expect(parseDatabaseRules("not json at all")).toEqual([]);
    expect(parseDatabaseRules("x".repeat(500_001))).toEqual([]);
  });
  it("classifies values", () => {
    expect(classifyRtdbValue(true, NOW).cls).toBe("open");
    expect(classifyRtdbValue("true", NOW).cls).toBe("open");
    expect(classifyRtdbValue("false", NOW).cls).toBe("deny");
    expect(classifyRtdbValue("auth != null", NOW).cls).toBe("signed-in");
    expect(classifyRtdbValue("auth.uid !== null", NOW).cls).toBe("signed-in");
    expect(classifyRtdbValue("now < 4102444800000", NOW).cls).toBe("test-mode");
    expect(classifyRtdbValue("now < 1500000000000", NOW).cls).toBe("deny");
    expect(classifyRtdbValue("$uid === auth.uid", NOW).cls).toBe("scoped");
    expect(classifyRtdbValue("auth != null && newData.isString()", NOW).cls).toBe("signed-in");
  });
});

describe("parseRulesFile resource limits", () => {
  const head = "rules_version = '2';\nservice cloud.firestore {\n";
  it("handles deep match nesting with many allows quickly", () => {
    const text = head + "match /a{\n".repeat(5000) + "allow read;\n".repeat(20000) + "}".repeat(5000);
    const t0 = Date.now();
    const out = parseRulesFile(text.slice(0, 490_000));
    expect(Date.now() - t0).toBeLessThan(500);
    expect(out.length).toBeLessThanOrEqual(5000);
  });
  it("caps recorded statements and scanned allow text", () => {
    const text = head + "match /docs/{id} {\n" + "allow read: if (\n".repeat(30000) + "}}";
    const t0 = Date.now();
    parseRulesFile(text);
    expect(Date.now() - t0).toBeLessThan(500);
    const many = head + "match /x/{id} {\n" + "allow read: if true;\n".repeat(20000) + "}}";
    expect(parseRulesFile(many).length).toBeLessThanOrEqual(5000);
  });
  it("still parses ordinary nested matches and shares paths", () => {
    const out = parseRulesFile(
      head +
        "match /databases/{d}/documents {\n match /users/{uid} {\n allow read: if request.auth.uid == uid;\n allow write: if request.auth.uid == uid;\n }\n}\n}",
    );
    expect(out).toHaveLength(2);
    expect(out[0]?.segments).toEqual(["users", "{uid}"]);
  });
});
