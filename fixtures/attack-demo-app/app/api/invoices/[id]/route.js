import { db } from "../../../../lib/db.js";
import { getSession } from "../../../../lib/session.js";
import { guardInvoice } from "../../../../lib/guard.js";

export async function GET(request, { params }) {
  const session = getSession(request);
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { data } = await db.from("invoices").select("*").eq("id", id).single();
  if (!guardInvoice(data, session)) return Response.json({ error: "not found" }, { status: 404 });
  return Response.json(data);
}
