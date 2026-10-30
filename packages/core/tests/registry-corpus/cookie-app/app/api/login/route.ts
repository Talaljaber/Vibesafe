import { cookies } from "next/headers";

export async function POST(req: Request) {
  const { token } = await req.json();
  cookies().set("session", token);
  return Response.json({ ok: true });
}
