import { NextResponse } from "next/server";

export async function POST(req: Request) {
  // Missing auth check
  const data = await req.json(); // Missing validation
  return NextResponse.json({ success: true, data });
}
