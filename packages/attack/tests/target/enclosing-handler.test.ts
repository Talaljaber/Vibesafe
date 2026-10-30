import { describe, expect, it } from "vitest";
import { enclosingHandler, handlerSpan } from "../../src/target/enclosing-handler.js";

const TWO = [
  "import { db } from '@/lib/db';", // 1
  "export async function GET(req) {", // 2
  "  return db.from('notes').select('*').eq('id', 1).single();", // 3
  "}", // 4
  "", // 5
  "export async function PATCH(req) {", // 6
  "  return db.from('notes').update({ a: 1 }).eq('id', 1);", // 7
  "}", // 8
].join("\n");

describe("enclosingHandler", () => {
  it("resolves GET then PATCH by line", () => {
    expect(enclosingHandler(TWO, 3)?.method).toBe("GET");
    expect(enclosingHandler(TWO, 7)?.method).toBe("PATCH");
    expect(enclosingHandler(TWO, 6)?.method).toBe("PATCH");
  });
  it("single handler spans to end of file", () => {
    const src = "export const GET = async () => {\n  return 1;\n};\n";
    const h = enclosingHandler(src, 2);
    expect(h?.method).toBe("GET");
    expect(h?.startLine).toBe(1);
    expect(h?.body).toContain("return 1");
  });
  it("returns undefined for a line before any handler", () => {
    expect(enclosingHandler(TWO, 1)).toBeUndefined();
    expect(enclosingHandler("const a = 1;", 1)).toBeUndefined();
  });
  it("scopes each span to its own handler", () => {
    const get = handlerSpan(TWO, "GET")!;
    expect(get.endLine).toBe(5);
    expect(get.body).not.toContain("update(");
    expect(handlerSpan(TWO, "PATCH")!.body).toContain("update(");
    expect(handlerSpan(TWO, "DELETE")).toBeUndefined();
  });
});
