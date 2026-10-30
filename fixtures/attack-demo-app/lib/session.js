const SESSIONS = {
  "alice-dev": { userId: "u_alice", role: "admin" },
  "bob-dev": { userId: "u_bob", role: "user" },
};

export function getSession(request) {
  const cookie = request.headers.get("cookie") ?? "";
  const m = /(?:^|;\s*)vs_session=([^;]+)/.exec(cookie);
  return (m && SESSIONS[m[1]]) || null;
}
