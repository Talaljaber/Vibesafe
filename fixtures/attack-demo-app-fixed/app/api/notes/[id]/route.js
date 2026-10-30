import { db } from "../../../../lib/db.js";
import { getSession } from "../../../../lib/session.js";

export async function GET(request, { params }) {
  const session = getSession(request);
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { data } = await db
    .from("notes")
    .select("*")
    .eq("id", id)
    .eq("user_id", session.userId)
    .single();
  if (!data) return Response.json({ error: "not found" }, { status: 404 });
  return Response.json(data);
}

export async function PATCH(request, { params }) {
  const session = getSession(request);
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { title } = await request.json();
  const { data } = await db
    .from("notes")
    .update({ title })
    .eq("id", id)
    .eq("user_id", session.userId)
    .single();
  if (!data) return Response.json({ error: "not found" }, { status: 404 });
  return Response.json(data);
}
