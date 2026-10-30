import { describe, expect, it } from "vitest";
import { preflightGet } from "../../src/plan/preflight.js";

const wrap = (body: string): string => `export async function GET(req) {\n  ${body}\n}\n`;

describe("preflightGet", () => {
  const cases: [string, string][] = [
    ["insert", "await db.from('a').insert({});"],
    ["update", "await db.from('a').update({});"],
    ["upsert", "await db.from('a').upsert({});"],
    ["delete", "await db.from('a').delete();"],
    ["deleteMany", "await prisma.a.deleteMany();"],
    ["updateMany", "await prisma.a.updateMany({});"],
    ["create", "await prisma.a.create({});"],
    ["createMany", "await prisma.a.createMany({});"],
    ["fetch POST", "await fetch(url, { method: 'POST' });"],
    ["fetch DELETE", 'await fetch(url, { headers: {}, method: "DELETE" });'],
    ["twilio", "await twilio.messages.send({});"],
    ["ses", "await ses.send(cmd);"],
    ["exec plain", "exec('ls');"],
    ["fetch PUT", "await fetch(url, { method: 'PUT' });"],
    ["fetch PATCH", "await fetch(url, { method: 'PATCH' });"],
    ["resend", "await resend.emails.send({});"],
    ["nodemailer", "await nodemailer.sendMail({});"],
    ["exec", "execSync('ls');"],
    ["spawn", "spawn('ls');"],
    ["fs write", "fs.writeFileSync('a', 'b');"],
    ["fs rm", "fs.rm('a');"],
    ["revalidatePath", "revalidatePath('/');"],
    ["revalidateTag", "revalidateTag('x');"],
    ["cookies set", "cookies().set('a', 'b');"],
    ["cookies delete", "cookies().delete('a');"],
  ];
  for (const [name, body] of cases) {
    it(`skips on ${name}`, () => {
      const r = preflightGet("/api/x", wrap(body));
      expect(r.skip).toBe(true);
      expect(r.reason).toBe("handler may write");
    });
  }

  it("does not skip a read-only handler", () => {
    expect(preflightGet("/api/notes/[id]", wrap("return db.from('n').select('*');")).skip).toBe(
      false,
    );
  });

  const SEGMENTS = [
    "seed",
    "reset",
    "delete",
    "remove",
    "logout",
    "signout",
    "cron",
    "migrate",
    "webhook",
    "send",
    "charge",
    "sync",
    "import",
    "purge",
    "clear",
    "wipe",
    "drop",
  ];
  for (const seg of SEGMENTS) {
    it(`skips risky path segment ${seg}`, () => {
      expect(preflightGet(`/api/${seg}`, wrap("return 1;")).skip).toBe(true);
      expect(preflightGet(`/api/${seg}/[id]`, wrap("return 1;")).skip).toBe(true);
    });
  }
  it("does not match segment substrings", () => {
    expect(preflightGet("/api/resetter", wrap("return 1;")).skip).toBe(false);
    expect(preflightGet("/api/notes", wrap("return 1;")).skip).toBe(false);
  });

  it("is scoped per handler: PATCH update does not skip GET", () => {
    const src = `${wrap("return db.from('notes').select('*');")}\nexport async function PATCH() {\n  await db.from('notes').update({}).eq('id', 1);\n}\n`;
    expect(preflightGet("/api/notes/[id]", src).skip).toBe(false);
  });
  it("skips when GET is exported by alias and the handler writes", () => {
    const src = `async function handler() {\n  await db.from('a').insert({});\n}\nexport { handler as GET, handler as POST };\n`;
    expect(preflightGet("/api/x", src).skip).toBe(true);
  });
  it("skips when GET is a wrapped export", () => {
    const src = `const h = async () => {\n  await db.from('a').insert({});\n};\nexport const GET = withAuth(h);\n`;
    expect(preflightGet("/api/x", src).skip).toBe(true);
  });
  it("skips when GET calls a writing helper above the export", () => {
    const src = `async function logVisit() {\n  await db.from('v').insert({});\n}\nexport async function GET() {\n  await logVisit();\n}\n`;
    expect(preflightGet("/api/x", src).skip).toBe(true);
  });
  it("a quoted method string in GET does not cut the span", () => {
    const src = `export async function GET(req) {\n  console.log(req.method);\n  await fetch(u, { method: "POST" });\n  await db.from('a').insert({});\n}\n`;
    expect(preflightGet("/api/x", src).skip).toBe(true);
  });
  it("skips when the GET handler itself writes", () => {
    const src = `export async function POST() {\n  return 1;\n}\n${wrap("await db.from('n').insert({});")}`;
    expect(preflightGet("/api/n", src).skip).toBe(true);
  });
});
