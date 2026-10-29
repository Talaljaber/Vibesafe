const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.users.findOne({ email, password });
  console.log("login", email);
  res.json({ user });
});

app.delete("/api/users/:id", async (req, res) => {
  await db.users.delete(req.params.id);
  res.json({ ok: true });
});

app.post("/api/notes", async (req, res) => {
  const note = await db.notes.create(req.body);
  res.json(note);
});

app.listen(3000, () => console.log("listening on http://localhost:3000"));
