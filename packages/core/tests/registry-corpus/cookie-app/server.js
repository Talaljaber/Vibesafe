const express = require("express");
const session = require("express-session");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, cookie: { secure: false } }));

app.post("/session", (req, res) => {
  res.cookie("token", jwt.sign({ id: req.body.id }, process.env.JWT_SECRET));
  res.json({ ok: true });
});

const router = express.Router();
router.post("/transfer", requireLogin, async (req, res) => {
  await transfer(req.user.id, req.body.to, req.body.amount);
  res.json({ ok: true });
});
app.use(router);

app.listen(3000);
