const mongoose = require("mongoose");
const { createHmac, randomBytes } = require("crypto");
const { createTokenForUser } = require("../services/authentication");

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    salt: {
      type: String,
    },
    password: {
      type: String,
      required: true,
    },
    profileImageURL: {
      type: String,
      default: "/images/default.png",
    },
    role: {
      type: String,
      enum: ["USER", "ADMIN"],
      default: "USER",
    },
  },
  { timestamps: true }
);

userSchema.pre("save", function (next) {
  const user = this;
  if (!user.isModified("password")) return next();

  const salt = randomBytes(16).toString("hex");
  const hashedPassword = createHmac("sha256", salt)
    .update(user.password)
    .digest("hex");
  
  // --- DEBUG LOGS FOR SIGNUP ---
  console.log("\n--- SIGNUP PROCESS ---");
  console.log("Original Password:", user.password);
  console.log("Salt Generated:", salt);
  console.log("Hashed Password to be Saved:", hashedPassword);
  // -------------------------

  this.salt = salt;
  this.password = hashedPassword;

  next();
});

userSchema.static(
  "matchPasswordAndGenerateToken",
  async function (email, password) {
    const user = await this.findOne({ email });
    if (!user) throw new Error("User not found!");

    const salt = user.salt;
    const hashedPassword = user.password;

    const userProvidedHash = createHmac("sha256", salt)
      .update(password)
      .digest("hex");

    // --- DEBUG LOGS FOR LOGIN ---
    console.log("\n--- LOGIN ATTEMPT ---");
    console.log("Password Provided by User:", password);
    console.log("Salt from Database:", salt);
    console.log("Hash from Database:", hashedPassword);
    console.log("Hash Generated from Provided Password:", userProvidedHash);
    // -------------------------

    if (hashedPassword !== userProvidedHash) {
      throw new Error("Incorrect Password");
    }
    const token = createTokenForUser(user);
    return token;
  }
);

const User = mongoose.models.user || mongoose.model("user", userSchema);

module.exports = User;