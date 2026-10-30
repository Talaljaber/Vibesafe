import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { FirebaseRulesDetector } from "../../src/detectors/firebase-rules-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const NOW = Date.UTC(2026, 9, 30);

const createContext = (
  files: Record<string, string>,
  config: Partial<ScanContext["config"]> = {},
  listed?: string[],
): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: listed ?? Object.keys(files),
  config: { rootPath: "/fake", ...config },
  readFile: async (f) => files[f] ?? "",
});

const run = async (
  files: Record<string, string>,
  config: Partial<ScanContext["config"]> = {},
  listed?: string[],
): Promise<Finding[]> => {
  const detector = new FirebaseRulesDetector(() => NOW);
  const ctx = createContext(files, config, listed);
  const findings = await detector.detect(ctx);
  expectRubric(findings);
  const again = await detector.detect(ctx);
  expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  return findings;
};

const summary = (fs: Finding[]): string[] =>
  fs.map(
    (f) => `${f.ruleId.replace("authorization/firebase-rules-", "")} ${f.severity}/${f.confidence}`,
  );

const fsRules = (...body: string[]): string =>
  [
    "rules_version = '2';",
    "service cloud.firestore {",
    "  match /databases/{database}/documents {",
    ...body,
    "  }",
    "}",
  ].join("\n");

const storageRules = (...body: string[]): string =>
  ["service firebase.storage {", "  match /b/{bucket}/o {", ...body, "  }", "}"].join("\n");

const ROOT = (rule: string): string => `    match /{document=**} { ${rule} }`;

describe("FirebaseRulesDetector: positives", () => {
  it("1. open read/write on the root is public-write critical/high", async () => {
    const f = await run({ "firestore.rules": fsRules(ROOT("allow read, write: if true;")) });
    expect(summary(f)).toEqual(["public-write critical/high"]);
    expect(f[0]?.file).toBe("firestore.rules");
    expect(f[0]?.line).toBe(4);
    expect(f[0]?.deployBlocking).toBe(true);
  });

  it("2. no condition is open", async () => {
    const f = await run({ "firestore.rules": fsRules(ROOT("allow read, write;")) });
    expect(summary(f)).toEqual(["public-write critical/high"]);
  });

  it("3. test mode with a future expiry", async () => {
    const f = await run({
      "firestore.rules": fsRules(
        ROOT("allow read, write: if request.time < timestamp.date(2099, 1, 1);"),
      ),
    });
    expect(summary(f)).toEqual(["test-mode critical/high"]);
    expect(f[0]?.plainEnglishProblem).toContain("2099-01-01");
  });

  it("4. any signed-in user on a private collection", async () => {
    const f = await run({
      "firestore.rules": fsRules(
        "    match /orders/{orderId} { allow read, write: if request.auth != null; }",
      ),
    });
    expect(summary(f)).toEqual(["any-signed-in high/medium"]);
  });

  it("5. any signed-in read on the root", async () => {
    const f = await run({
      "firestore.rules": fsRules(ROOT("allow read: if request.auth != null;")),
    });
    expect(summary(f)).toEqual(["any-signed-in high/high"]);
  });

  it("6. functions are inlined", async () => {
    const f = await run({
      "firestore.rules": [
        "service cloud.firestore {",
        "  function signedIn() { return request.auth != null; }",
        "  match /databases/{database}/documents {",
        "    match /messages/{id} { allow update: if signedIn(); }",
        "  }",
        "}",
      ].join("\n"),
    });
    expect(summary(f)).toEqual(["any-signed-in high/medium"]);
  });

  it("7. public read of a directory-type collection", async () => {
    const f = await run({
      "firestore.rules": fsRules("    match /users/{id} { allow read: if true; }"),
    });
    expect(summary(f)).toEqual(["public-read high/medium"]);
  });

  it("8. storage root open", async () => {
    const f = await run({
      "storage.rules": storageRules("    match /{allPaths=**} { allow read, write: if true; }"),
    });
    expect(summary(f)).toEqual(["public-write critical/high"]);
  });

  it("9. RTDB open root gives a finding per key", async () => {
    const f = await run({
      "database.rules.json": '{\n  "rules": {\n    ".read": true,\n    ".write": true\n  }\n}',
    });
    expect(f.map((x) => [x.ruleId.split("-").slice(2).join("-"), x.line, x.severity])).toEqual([
      ["public-read", 3, "critical"],
      ["public-write", 4, "critical"],
    ]);
  });

  it("10. RTDB test mode", async () => {
    const f = await run({
      "database.rules.json":
        '{ "rules": { ".read": "now < 4102444800000", ".write": "now < 4102444800000" } }',
    });
    expect(summary(f)).toEqual(["test-mode high/high", "test-mode critical/high"]);
  });

  it("11. firebase.json names a rules file with a non-standard name", async () => {
    const f = await run(
      {
        "firebase.json": '{ "firestore": { "rules": "config/db.rules" } }',
        "config/db.rules": fsRules(ROOT("allow read, write: if true;")),
      },
      {},
      ["firebase.json"],
    );
    expect(summary(f)).toEqual(["public-write critical/high"]);
    expect(f[0]?.file).toBe("config/db.rules");
  });

  it("12. validation is neutral next to a sign-in check", async () => {
    const f = await run({
      "firestore.rules": fsRules(
        ROOT("allow write: if request.auth != null && request.resource.data.title is string;"),
      ),
    });
    expect(summary(f)).toEqual(["any-signed-in high/high"]);
  });

  it("13. OR with true is open", async () => {
    const f = await run({
      "firestore.rules": fsRules(ROOT("allow read: if isOwner() || true;")),
    });
    expect(summary(f)).toEqual(["public-read critical/high"]);
  });

  it("14. an all-$ RTDB path is the root", async () => {
    const f = await run({ "database.rules.json": '{"rules": {"$any": {".read": true}}}' });
    expect(summary(f)).toEqual(["public-read critical/high"]);
  });

  it("15. storage root read is capped at high/medium", async () => {
    const f = await run({
      "storage.rules": storageRules("    match /{allPaths=**} { allow read; }"),
    });
    expect(summary(f)).toEqual(["public-read high/medium"]);
  });

  it("16. signed-in reads of directory and private names", async () => {
    const dir = await run({
      "firestore.rules": fsRules(
        "    match /users/{userId} { allow read: if request.auth != null; }",
      ),
    });
    expect(summary(dir)).toEqual(["any-signed-in medium/low"]);
    const priv = await run({
      "firestore.rules": fsRules("    match /orders/{id} { allow read: if request.auth != null; }"),
    });
    expect(summary(priv)).toEqual(["any-signed-in medium/medium"]);
  });

  it("17. firebase.json multi-database array form", async () => {
    const f = await run(
      {
        "firebase.json": JSON.stringify({
          firestore: [
            { database: "(default)", rules: "firestore.rules" },
            { database: "analytics", rules: "db/analytics.rules" },
            { database: "x", rules: 5 },
          ],
        }),
        "firestore.rules": fsRules(
          "    match /users/{userId} { allow read, write: if request.auth.uid == userId; }",
        ),
        "db/analytics.rules": fsRules(ROOT("allow read, write: if true;")),
      },
      {},
      ["firebase.json", "firestore.rules"],
    );
    expect(summary(f)).toEqual(["public-write critical/high"]);
    expect(f[0]?.file).toBe("db/analytics.rules");
  });

  it("discovers files named in firebase.json only for the listed files under targetFiles", async () => {
    const files = {
      "firebase.json": '{ "storage": { "rules": "config/s.rules" } }',
      "config/s.rules": storageRules("    match /{allPaths=**} { allow write; }"),
    };
    expect(await run(files, { targetFiles: ["firebase.json"] }, ["firebase.json"])).toEqual([]);
    expect(
      summary(
        await run(files, { targetFiles: ["config/s.rules"] }, ["firebase.json", "config/s.rules"]),
      ),
    ).toEqual(["public-write critical/high"]);
  });

  it("reports a multi-line statement with endLine and a stable id", async () => {
    const f = await run({
      "firestore.rules": fsRules(
        "    match /{document=**} {",
        "      allow read, write:",
        "        if true;",
        "    }",
      ),
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.line).toBe(5);
    expect(f[0]?.endLine).toBe(6);
    expect(f[0]?.evidence).toBe("allow read, write:");
  });

  it("caps findings per rule per file with a summary", async () => {
    const body = Array.from(
      { length: 30 },
      (_, i) => `    match /orders${i}/{id} { allow write: if true; }`,
    );
    const f = await run({ "firestore.rules": fsRules(...body) });
    expect(f).toHaveLength(26);
  });

  it("scans every rules file by name pattern", async () => {
    const rules = fsRules(ROOT("allow write: if true;"));
    const f = await run({ "firebase/firestore.dev.rules": rules, "storage-prod.rules": rules });
    expect(f.map((x) => x.file).sort()).toEqual([
      "firebase/firestore.dev.rules",
      "storage-prod.rules",
    ]);
  });
});

describe("FirebaseRulesDetector: silent idioms", () => {
  const silent: [string, string][] = [
    [
      "owner scoped",
      "    match /users/{userId} { allow read, write: if request.auth != null && request.auth.uid == userId; }",
    ],
    [
      "public posts with owner edits",
      "    match /posts/{postId} { allow read: if true; allow create: if request.auth != null; allow update, delete: if request.auth.uid == resource.data.authorId; }",
    ],
    [
      "admin claim writes",
      "    match /products/{id} { allow read: if true; allow write: if request.auth.token.admin == true; }",
    ],
    [
      "owner helper function",
      "    function isOwner(uid) { return request.auth != null && request.auth.uid == uid; }\n    match /notes/{uid}/{doc=**} { allow read, write: if isOwner(uid); }",
    ],
    ["locked default", ROOT("allow read, write: if false;")],
    ["expired test mode", ROOT("allow read, write: if request.time < timestamp.date(2020, 1, 1);")],
    ["public contact form", "    match /contact/{id} { allow create: if true; }"],
    ["commented-out rule", "    // match /{document=**} { allow read, write: if true; }"],
    ["block-commented rule", "    /* match /{document=**} { allow read, write: if true; } */"],
    [
      "public catalog read",
      "    match /catalog/{id} { allow read: if true; allow write: if false; }",
    ],
    [
      "membership lookup",
      "    match /teams/{id} { allow read, write: if exists(/databases/$(database)/documents/members/$(request.auth.uid)); }",
    ],
    ["create only signed-in", "    match /orders/{id} { allow create: if request.auth != null; }"],
  ];
  for (const [name, body] of silent) {
    it(name, async () => {
      expect(await run({ "firestore.rules": fsRules(body) })).toEqual([]);
    });
  }

  it("storage avatars: public read, owner write", async () => {
    const f = await run({
      "storage.rules": storageRules(
        "    match /avatars/{uid}/{file} { allow read; allow write: if request.auth.uid == uid && request.resource.size < 5 * 1024 * 1024; }",
      ),
    });
    expect(f).toEqual([]);
  });

  it("storage public folder read", async () => {
    const f = await run({
      "storage.rules": storageRules("    match /public/{allPaths=**} { allow read; }"),
    });
    expect(f).toEqual([]);
  });

  it("RTDB per-user and locked rules", async () => {
    expect(
      await run({
        "database.rules.json":
          '{"rules": {"users": {"$uid": {".read": "$uid === auth.uid", ".write": "$uid === auth.uid"}}}}',
      }),
    ).toEqual([]);
    expect(
      await run({ "database.rules.json": '{"rules": {".read": false, ".write": false}}' }),
    ).toEqual([]);
  });

  it("a rules mention in a source file or comment is ignored", async () => {
    expect(
      await run({
        "src/rules.ts": 'const r = "allow read, write: if true;";',
        "firestore.rules": "service cloud.firestore {\n  // allow read, write: if true;\n}",
      }),
    ).toEqual([]);
  });

  it("a .rules file without a service header", async () => {
    expect(await run({ "custom.rules": "allow read: if true;" })).toEqual([]);
    expect(
      await run({ "firestore.rules": "match /{document=**} { allow read: if true; }" }),
    ).toEqual([]);
  });

  it("test and fixture paths need includeTests", async () => {
    const files = { "tests/firestore.rules": fsRules(ROOT("allow read, write: if true;")) };
    expect(await run(files)).toEqual([]);
    expect(summary(await run(files, { includeTests: true }))).toEqual([
      "public-write critical/high",
    ]);
  });

  it("unparseable database rules produce nothing and do not throw", async () => {
    expect(await run({ "database.rules.json": '{ "rules": { ".read": ' })).toEqual([]);
    expect(await run({ "firebase.json": "{ not json" })).toEqual([]);
  });

  it("rejects firebase.json rules paths that escape the project", async () => {
    expect(
      await run(
        {
          "firebase.json": '{ "firestore": { "rules": "../outside.rules" } }',
          "../outside.rules": fsRules(ROOT("allow write: if true;")),
        },
        {},
        ["firebase.json"],
      ),
    ).toEqual([]);
  });
});

describe("FirebaseRulesDetector: review round 1 hardening", () => {
  const OPEN =
    "service cloud.firestore {\n match /databases/{d}/documents {\n match /{document=**} {\n allow read, write: if true;\n }\n }\n}\n";

  it("scans rules named by a firebase.json that starts with a BOM", async () => {
    const out = await run(
      {
        "firebase.json": '\uFEFF{"firestore":{"rules":"config/db.rules"}}',
        "config/db.rules": OPEN,
      },
      {},
      ["firebase.json", "config/db.rules"],
    );
    expect(out.length).toBeGreaterThan(0);
  });

  it("does not leak a secret into the problem text of a minified RTDB file", async () => {
    const secret = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
    let body = "";
    for (let i = 0; i < 300; i++) body += `"c${i}":{".read":true,".write":true},`;
    const min = `{"x":"${secret}","rules":{${body}"z":{}}}`;
    const t0 = Date.now();
    const out = await run({ "database.rules.json": min });
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(out.length).toBeGreaterThan(0);
    for (const f of out) {
      expect(f.plainEnglishProblem).not.toContain(secret);
      expect(f.evidence ?? "").not.toContain(secret);
      expect(f.plainEnglishProblem.length).toBeLessThan(2000);
    }
  });

  it("survives a deep and wide RTDB file quickly", async () => {
    let s = '{"rules":';
    for (let i = 0; i < 4000; i++) s += '{"$a":';
    s += '{".read":true}';
    s += "}".repeat(4000) + "}";
    let wide = '{"rules":{';
    for (let i = 0; i < 8000; i++) wide += `"k${i}":{".read":true},`;
    wide += '"z":{}}}';
    const t0 = Date.now();
    await run({ "a.rules.json": s, "b.rules.json": wide });
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it("stays fast on repeated unterminated match/function keywords", async () => {
    const text = "service cloud.firestore {\n" + "match /{\nfunction f\n".repeat(20000);
    const t0 = Date.now();
    await run({ "firestore.rules": text + "allow read: if true;" });
    expect(Date.now() - t0).toBeLessThan(3000);
  });

  it("words the any-signed-in problem without doubled phrases", async () => {
    const out = await run({
      "firestore.rules":
        "service cloud.firestore {\n match /databases/{d}/documents {\n match /orders/{id} {\n allow read: if request.auth != null;\n }\n }\n}\n",
    });
    const p = out[0]?.plainEnglishProblem ?? "";
    expect(p).not.toMatch(/records in records|every record in the/);
    expect(p).not.toContain("read or change");
    expect(p).toContain("the records in `orders`");
  });
});
