const { Router } = require("express");
const User = require("../models/user");
const upload = require("../services-temp/cloudinary");
const { createTokenForUser } = require("../services-temp/authentication");

const router = Router();

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
      profileImageURL: req.file.path,
    },
    { new: true }
  );

  const token = createTokenForUser(user);
  return res.cookie("token", token).redirect("/user/profile");
});

module.exports = router;
