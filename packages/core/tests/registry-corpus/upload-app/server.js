const express = require("express");
const multer = require("multer");
const fileUpload = require("express-fileupload");

const app = express();

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ dest: "uploads/", storage });

app.use("/files", express.static("uploads"));
app.use("/avatars", fileUpload());

app.post("/api/documents", upload.single("document"), (req, res) => {
  res.json({ name: req.file.filename });
});

app.post("/api/avatars", (req, res) => {
  const avatar = req.files.avatar;
  avatar.mv(`./public/avatars/${avatar.name}`);
  res.json({ ok: true });
});

app.listen(3000);
