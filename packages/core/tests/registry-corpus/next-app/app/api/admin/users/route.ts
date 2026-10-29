import { getServerSession } from "next-auth";
import { db } from "@/lib/db";

export async function DELETE(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { userId } = await req.json();
  await db.user.delete({ where: { id: userId } });
  return Response.json({ ok: true });
}
