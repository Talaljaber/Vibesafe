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
    ["stripe", "await stripe.charges.create({});"],
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

  for (const seg of ["seed", "reset", "logout", "cron", "webhook", "wipe", "drop", "sync"]) {
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
  it("skips when the GET handler itself writes", () => {
    const src = `export async function POST() {\n  return 1;\n}\n${wrap("await db.from('n').insert({});")}`;
    expect(preflightGet("/api/n", src).skip).toBe(true);
  });
});
