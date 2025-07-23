const { Router } = require("express");
const multer = require("multer");
const path = require("path");
const User = require("../models/user");
const { createTokenForUser } = require("../Services/Authentication");

const router = Router();

// Multer storage configuration for profile pictures
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.resolve(`./public/images/profiles/`));
  },
  filename: function (req, file, cb) {
    const fileName = `${Date.now()}-${file.originalname}`;
    cb(null, fileName);
  },
});

const upload = multer({ storage: storage });

router.get("/signin", (req, res) => {
  return res.render("signin");
});

router.get("/signup", (req, res) => {
  return res.render("signup");
});

router.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  try {
    const token = await User.matchPasswordAndGenerateToken(email, password);
    return res.cookie("token", token).redirect("/");
  } catch (error) {
    return res.render("signin", {
      error: "Incorrect Email or Password",
    });
  }
});

router.get("/logout", (req, res) => {
  res.clearCookie("token").redirect("/");
});

router.post("/signup", async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    await User.create({ fullName, email, password });
    return res.redirect("/");
  } catch (error) {
    return res.render("signup", {
      error: "User with this email already exists.",
    });
  }
});

router.get("/profile", (req, res) => {
  if (!req.user) return res.redirect("/user/signin");
  return res.render("profile", {
    user: req.user,
  });
});

router.post("/profile", upload.single("profileImage"), async (req, res) => {
  if (!req.user) return res.redirect("/user/signin");

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      profileImageURL: `/images/profiles/${req.file.filename}`,
    },
    { new: true }
  );

  const token = createTokenForUser(user);

  return res.cookie("token", token).redirect("/user/profile");
});

module.exports = router;