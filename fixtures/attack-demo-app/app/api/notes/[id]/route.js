import { db } from "../../../../lib/db.js";
import { getSession } from "../../../../lib/session.js";

export async function GET(request, { params }) {
  const session = getSession(request);
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { data } = await db.from("notes").select("*").eq("id", id).single();
  return Response.json(data);
}

export async function PATCH(request, { params }) {
  const session = getSession(request);
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { title } = await request.json();
  const { data } = await db.from("notes").update({ title }).eq("id", id).single();
  return Response.json(data);
}
