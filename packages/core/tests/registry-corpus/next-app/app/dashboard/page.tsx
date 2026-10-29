"use client";

import { useEffect, useState } from "react";

export default function Dashboard({ bio }: { bio: string }) {
  const [stats, setStats] = useState<unknown>(null);
  useEffect(() => {
    fetch("http://localhost:4000/api/stats").then(async (r) => setStats(await r.json()));
  }, []);
  console.log(stats);
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
