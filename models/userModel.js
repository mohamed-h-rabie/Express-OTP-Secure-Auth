import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { type } from "os";
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "User must have a name"],
  },
  email: {
    type: String,
    unique: true,
    required: [true, "User must have a email"],
  },
  password: {
    type: String,
    required: [true, "User must have a password"],
    select: false,
  },
  photo: String,
  active: {
    default: true,
    type: Boolean,
    select: false,
  },
  createdAt: {
    type: Date,
    default: Date.now(),
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  otp: {
    type: String,
  },
  otpExpiry: {
    type: Date,
  },
  otpAttempts: {
    type: Number,
    default: 0,
  },
  passwordResetVerified: {
    type: Boolean,
  },
  passwordChangeAt: {
    type: Date,
  },
});
userSchema.pre("save", async function (next) {
  const user = this;
  if (!user.isModified("password")) return next();

  user.password = await bcrypt.hash(user.password, 10);
  next();
});

userSchema.pre("save", function (next) {
  const user = this;
  if (!user.isModified("password") || user.isNew) return next();
  // user.passwordChangeAt = Date.now() - 1000;
  user.passwordChangeAt = Date.now();
  next();
});
userSchema.methods.changePasswordAfter = function (JWTIAT) {
  const user = this;
  if (user.passwordChangeAt) {
    // const time = Math.floor(user.passwordChangeAt /1000)
    const time = Math.floor(user.passwordChangeAt);
    if (time > JWTIAT) return true;
  }
  return false;
};
userSchema.methods.isCorrectPassword = async function (
  enteredPassword,
  userPassword
) {
  return await bcrypt.compare(enteredPassword, userPassword);
};
const User = mongoose.model("User", userSchema);
export default User;
