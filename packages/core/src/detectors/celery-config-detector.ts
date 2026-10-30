import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { pythonStatements, scanPythonLines } from "./utils/python-source.js";
import { maskPython } from "./utils/python-taint.js";

const SERIALIZER_KEY_RE =
  /\b(?:CELERY_TASK_SERIALIZER|CELERY_RESULT_SERIALIZER|task_serializer|result_serializer)\s*=\s*(["'])~+\1/g;
const ACCEPT_KEY_RE = /\b(?:CELERY_ACCEPT_CONTENT|accept_content)\s*=\s*/g;

/**
 * Celery configured to use pickle (`security_config/celery-pickle-serializer`): the
 * task/result serializer settings or an accept_content list containing "pickle". Anyone who
 * can write to the broker or result backend can then run code on the workers. Line based:
 * values built from variables or settings split across modules are not followed.
 */
export class CeleryConfigDetector implements Detector {
  id = "celery-config-detector";
  name = "Celery Configuration";
  category = "security_config" as const;
  description = "Detects Celery configured with the pickle serializer or accepting pickle content.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        if (classifyPath(file) !== "python") continue;
        if (isTestOrFixturePath(file)) continue;
        const content = await context.readFile(file);
        if (!content || !content.includes("pickle")) continue;
        findings.push(...this.scanFile(file, content));
      } catch {
        // a detector never throws
      }
    }
    return findings;
  }

  private scanFile(file: string, content: string): Finding[] {
    const lines = scanPythonLines(content);
    const hits: Array<{ start: number; end: number; head: string }> = [];
    for (const st of pythonStatements(lines)) {
      if (!st.stmt.includes("pickle")) continue;
      const mask = maskPython(st.stmt);
      let hit = false;
      for (const m of mask.matchAll(SERIALIZER_KEY_RE)) {
        const valueStart = m.index + m[0].length - m[0].length + m[0].search(/["']/) + 1;
        if (st.stmt.slice(valueStart, valueStart + 6) === "pickle") hit = true;
      }
      if (!hit) {
        for (const m of mask.matchAll(ACCEPT_KEY_RE)) {
          const from = m.index + m[0].length;
          const close = mask.slice(from).search(/[\])}]/);
          const raw = st.stmt.slice(from, close < 0 ? undefined : from + close);
          if (/["']pickle["']/.test(raw)) hit = true;
        }
      }
      if (hit) hits.push({ start: st.start, end: st.end, head: st.head.trim() });
    }
    const out: Finding[] = [];
    for (let i = 0; i < hits.length; i++) {
      const first = hits[i]!;
      let end = first.end;
      let evidence = first.head;
      while (i + 1 < hits.length && hits[i + 1]!.start <= end + 1) {
        i++;
        end = hits[i]!.end;
        evidence += "\n" + hits[i]!.head;
      }
      out.push(
        makeFinding({
          category: "security_config",
          ruleId: "security_config/celery-pickle-serializer",
          title: "Celery Uses the Pickle Serializer",
          severity: "medium",
          confidence: "high",
          file,
          line: first.start + 1,
          ...(end > first.start ? { endLine: end + 1 } : {}),
          evidence,
          discriminator: "celery-pickle",
          plainEnglishProblem:
            "Celery is configured to serialize tasks or results with pickle, or to accept pickle messages.",
          whyItMatters:
            "Unpickling runs code chosen by whoever wrote the message. Anyone who can reach the broker (Redis, RabbitMQ) or the result backend can execute commands on your workers.",
          fixSteps: [
            'Set task_serializer and result_serializer to "json".',
            'Set accept_content to ["json"] so pickle messages are rejected.',
            "Send ids and plain data in task arguments instead of Python objects.",
          ],
          aiFixPrompt:
            "This Celery configuration enables the pickle serializer or accepts pickle content. Change task_serializer, result_serializer and accept_content (or the CELERY_* equivalents) to JSON only, and adjust any task that passes Python objects so it passes ids or plain JSON data instead.",
        }),
      );
    }
    return out;
  }
}
