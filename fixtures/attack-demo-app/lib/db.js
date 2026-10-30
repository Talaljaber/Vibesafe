// In-memory store with a Supabase-shaped query API. Demo only.
const tables = {
  users: [
    { id: "u_alice", user_id: "u_alice", email: "alice@example.test", role: "admin" },
    { id: "u_bob", user_id: "u_bob", email: "bob@example.test", role: "user" },
  ],
  notes: [
    { id: "n_alice_1", user_id: "u_alice", title: "Alice private note" },
    { id: "n_bob_1", user_id: "u_bob", title: "Bob private note" },
  ],
  invoices: [
    { id: "inv_alice_1", user_id: "u_alice", amount: 120 },
    { id: "inv_bob_1", user_id: "u_bob", amount: 340 },
  ],
};

function builder(table, patch) {
  const filters = [];
  const run = () => {
    const rows = (tables[table] ?? []).filter((r) => filters.every(([c, v]) => r[c] === v));
    if (patch) for (const r of rows) Object.assign(r, patch);
    return rows;
  };
  const b = {
    select() {
      return b;
    },
    eq(col, val) {
      filters.push([col, val]);
      return b;
    },
    single() {
      const row = run()[0];
      return Promise.resolve(
        row ? { data: row, error: null } : { data: null, error: { message: "not found" } },
      );
    },
    then(resolve, reject) {
      return Promise.resolve({ data: run(), error: null }).then(resolve, reject);
    },
  };
  return b;
}

export const db = {
  from(table) {
    return {
      select: () => builder(table).select(),
      update: (obj) => builder(table, obj),
    };
  },
};
