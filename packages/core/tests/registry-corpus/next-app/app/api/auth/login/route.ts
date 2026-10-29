import { db } from "@/lib/db";

export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await db.user.findFirst({ where: { email, password } });
  return Response.json({ user });
}
