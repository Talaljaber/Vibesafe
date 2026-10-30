import { db } from "../../../../lib/db.js";

export async function GET() {
  const { data } = await db.from("users").select("*");
  return Response.json({ users: data });
}
