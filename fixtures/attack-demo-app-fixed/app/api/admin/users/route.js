import { db } from "../../../../lib/db.js";
import { getSession } from "../../../../lib/session.js";

export async function GET(request) {
  const session = getSession(request);
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
  if (session.role !== "admin") return Response.json({ error: "forbidden" }, { status: 403 });
  const { data } = await db.from("users").select("*");
  return Response.json({ users: data });
}
