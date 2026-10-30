import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { CeleryConfigDetector } from "../../src/detectors/celery-config-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as never,
  files: Object.keys(files),
  config: { targetFiles: Object.keys(files) } as never,
  readFile: async (f) => files[f] ?? "",
});
const run = (src: string, file = "proj/settings/base.py") =>
  new CeleryConfigDetector().detect(ctx({ [file]: src }));

describe("celery-config-detector", () => {
  it("flags the pickle task serializer", async () => {
    const f = await run('CELERY_TASK_SERIALIZER = "pickle"\n');
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "security_config/celery-pickle-serializer",
      severity: "medium",
      confidence: "high",
      line: 1,
    });
    expectRubric(f);
  });

  it("reports adjacent accept_content and serializer lines as one finding with an endLine", async () => {
    const f = await run(
      'CELERY_BROKER_URL = "redis://x"\nCELERY_ACCEPT_CONTENT = ["json", "pickle"]\nCELERY_TASK_SERIALIZER = \'pickle\'\nNOTIFIER = 1\n',
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 2, endLine: 3 });
  });

  it("flags app.conf.update(...) and attribute form, separate lines give separate findings", async () => {
    const f = await run(
      'app.conf.update(task_serializer="pickle", result_serializer="json")\n\nx = 1\n\napp.conf.accept_content = ["pickle"]\n',
      "proj/celery.py",
    );
    expect(f).toHaveLength(2);
    expect(f.map((x) => x.line)).toEqual([1, 5]);
  });

  it("has stable ids", async () => {
    const a = await run('result_serializer = "pickle"\n');
    const b = await run('result_serializer = "pickle"\n');
    expect(a[0]!.id).toBe(b[0]!.id);
  });

  it("is silent for json, comments, unrelated variables and other file kinds", async () => {
    expect(
      await run(
        'CELERY_TASK_SERIALIZER = "json"\nCELERY_ACCEPT_CONTENT = ["json"]\n# CELERY_TASK_SERIALIZER = "pickle"\nCACHE_FORMAT = "pickle"\nPICKLE_PROTOCOL = 4\n',
      ),
    ).toHaveLength(0);
    expect(await run('task_serializer = "pickle"\n', "src/config.ts")).toHaveLength(0);
    expect(await run('task_serializer = "pickle"\n', "app/tests/test_cfg.py")).toHaveLength(0);
  });
});
