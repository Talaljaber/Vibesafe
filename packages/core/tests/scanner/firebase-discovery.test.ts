import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { classifyInfraFile } from "@talaljaber/vibesafe-shared";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { classifyPath } from "../../src/detectors/utils/file-kind.js";

describe("firebase rules file kind", () => {
  const matches = [
    "firestore.rules",
    "storage.rules",
    "firestore.dev.rules",
    "firestore-prod.rules",
    "firebase/firestore.rules",
    "Firestore.Rules",
  ];
  const nonMatches = [
    "database.rules.json",
    "rules.txt",
    "my.rules",
    "firestore.rules.bak",
    "notes.rules",
    "firestore.json",
  ];

  it("classifies the matching names", () => {
    for (const f of matches) {
      expect(classifyInfraFile(f), f).toBe("firebase-rules");
      expect(classifyPath(f), f).toBe("firebase-rules");
    }
  });

  it("does not classify the others", () => {
    for (const f of nonMatches) {
      expect(classifyInfraFile(f), f).not.toBe("firebase-rules");
      expect(classifyPath(f), f).not.toBe("firebase-rules");
    }
    expect(classifyPath("database.rules.json")).toBe("json");
  });
});

describe("discovery of firebase rules files", () => {
  let root: string;

  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-firebase-"));
    for (const f of [
      "firestore.rules",
      "storage.rules",
      "firebase/firestore.dev.rules",
      "database.rules.json",
      "firebase.json",
      "notes.rules",
      "my.rules",
    ]) {
      const full = path.join(root, f);
      await fs.mkdir(path.dirname(full), { recursive: true });
      await fs.writeFile(full, "x\n");
    }
  });

  afterAll(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("returns the rules files and not unrelated .rules files", async () => {
    const found = (await new FileDiscovery(root).discoverFiles())
      .map((f) => f.replace(/\\/g, "/"))
      .sort();
    expect(found).toEqual(
      [
        "database.rules.json",
        "firebase.json",
        "firebase/firestore.dev.rules",
        "firestore.rules",
        "storage.rules",
      ].sort(),
    );
  });
});
