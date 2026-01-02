import User from "../models/userModel.js";
import nodemailer from "nodemailer";
import otpGenerator from "otp-generator";
import crypto from "crypto";
import jwt from "jsonwebtoken";
const hashOtp = (otp) => {
  return crypto.createHash("sha256").update(otp).digest("hex");
};
function generateJWT(id) {
  console.log(id);

  return jwt.sign({ id }, process.env.JWT_KEY, {
    expiresIn: process.env.JWT_EXPIRES,
  });
}
const constantTimeCompare = (a, b) => {
  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
};
const sendOTPCode = async (userEmail) => {
  const OTP_Code = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
    digits: true,
  });
  console.log(OTP_Code);
  const otp = hashOtp(OTP_Code);
  const expiryTime = new Date(Date.now() + 10 * 60 * 1000); //after 10 min
  try {
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    await transporter.sendMail({
      to: userEmail,
      subject: "✅ Verify Your Email - OTP Code",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>Email Verification</h2>
          <p>Your OTP code is: <strong style="font-size: 24px;">${OTP_Code}</strong></p>
          <p>This code will expire in <strong>10 minutes</strong>.</p>
          <p style="color: #d32f2f;">⚠️ Don't share this code with anyone.</p>
        </div>
      `,
    });
    return { otp, expiryTime };
  } catch (error) {
    console.log(error);
  }
};

const signUp = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      if (existingUser.isVerified) {
        return res
          .status(401)
          .json({ message: "this user has already account" });
      }
      const { otp, expiryTime } = await sendOTPCode(existingUser.email);
      existingUser.otp = otp;
      existingUser.otpExpiry = expiryTime;
      existingUser.otpAttempts = 0;

      existingUser.password = password;
      existingUser.name = name;

      await existingUser.save();

      return res.status(200).json({
        message:
          "We found your account! A new OTP has been sent to your email.",
        action: "redirect_to_verify",
        data: {
          email: existingUser.email,
          name: existingUser.name,
        },
      });
    }

    const user = await User.create({ name, email, password });
    const { otp, expiryTime } = await sendOTPCode(user.email);
    user.otp = otp;
    user.otpExpiry = expiryTime;
    await user.save();
    res.status(200).json({
      message: "OTP sent successfully. Please check your email.",
      data: {
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    res.status(400).json({
      message: "success",
      error: error?.message,
    });
  }
};

const requestNewOTP = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "You should Signup First" });
  }
  const { otp, expiryTime } = await sendOTPCode(email);
  user.otp = otp;
  user.otpExpiry = expiryTime;
  user.otpAttempts = 0;
  await user.save();
  res.status(200).json({
    message: "success",
    data: {
      user,
    },
  });
};
const verifyUser = async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(401).json({ message: "email or otp in not in body" });
    }
    const user = await User.findOne({ email });
    if (user.isVerified) {
      return res
        .status(401)
        .json({ message: "this user has already Verified" });
    }
    if (!user || !user.otp || !user.otpExpiry) {
      return res.status(400).json({ message: "Invalid request" });
    }
    // Check expiry
    if (user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP has expired" });
    }
    if (user.otpAttempts >= 5) {
      return res.status(429).json({
        message: "Too many failed attempts. Request a new OTP.",
      });
    }
    const hashedOTP = hashOtp(otp);
    if (!constantTimeCompare(user.otp, hashedOTP)) {
      console.log("heeellllo");
      user.otpAttempts += 1;
      await user.save();

      return res.status(400).json({
        message: "Invalid OTP",
        attemptsLeft: 5 - user.otpAttempts,
      });
    }
    user.otp = undefined;
    user.otpExpiry = undefined;
    user.otpAttempts = undefined;
    user.isVerified = true;
    await user.save();
    const token = generateJWT(user.id);
    res.status(200).json({ message: "Account verified successfully.", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const signIn = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (!user.isVerified) {
      return res.status(401).json({
        message: "User not verified , you should verify you account first",
      });
    }
    const isCorrectPassword = await user.isCorrectPassword(
      password,
      user.password
    );

    if (!isCorrectPassword) {
      console.log({ message: "Invalid email or password" });

      return res.status(401).json({ message: "Invalid email or password" });
    }
    const token = generateJWT(user.id);
    res.status(200).json({
      message: "You are successfully Logined",
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error });
  }
};

const protectRoute = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) {
    return res.status(401).json({
      message: "Not Authorized, no token",
    });
  }
  // console.log(token);

  const decoded = jwt.verify(token, process.env.JWT_KEY);
  console.log(decoded);

  const user = await User.findById(decoded.id);
  if (!user) {
    res.status(401).json({
      message: "the user that belong to this token become not found",
    });
  }

  const userChangePasswordAfter = user.changePasswordAfter(decoded.iat);

  if (userChangePasswordAfter) {
    res.status(401).json({
      message: "You should login again",
    });
  }
  req.user = user;
  next();
};

const forgeetPassword = async (req, res) => {
  //getUserdata from email
  //create passwordresetToken
  //send it with mail

  try {
    const email = req.body.email;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({
        message: "this user not found , please login",
      });

    const { otp, expiryTime } = await sendOTPCode(email);
    user.otp = otp;
    user.otpExpiry = expiryTime;
    user.passwordResetVerified = false;
    user.otpAttempts = 0;
    await user.save({ validateBeforeSave: false });
    res.status(200).json({
      status: "success",
      message: "OTP sent to your email!",
      email,
    });
  } catch (error) {
    res.status(400).json({
      message: "success",
      error: error?.message,
    });
  }

  // in reset password
  // take otp and compare it with in db (otp attempts and expiry time )
  // add time when we update password
  // and update pass in db
};

const verifyResetPassword = async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(401).json({ message: "email or otp in not in body" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        message: "this user not found , please login",
      });
    }
    if (!user.otp || !user.otpExpiry) {
      return res.status(400).json({ message: "Invalid request" });
    }
    // Check expiry
    if (user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP has expired" });
    }
    if (user.otpAttempts >= 5) {
      return res.status(429).json({
        message: "Too many failed attempts. Request a new OTP.",
      });
    }
    const hashedOTP = hashOtp(otp);
    if (!constantTimeCompare(user.otp, hashedOTP)) {
      console.log("heeellllo");
      user.otpAttempts += 1;
      await user.save();

      return res.status(400).json({
        message: "Invalid OTP",
        attemptsLeft: 5 - user.otpAttempts,
      });
    }
    user.otp = undefined;
    user.otpAttempts = undefined;
    user.passwordResetVerified = true;
    await user.save();
    res.status(200).json({ message: "You can reset Your Password Now" });
  } catch (error) {
    res.status(400).json({
      message: error,
    });
  }
};
// reset password
const resetPassword = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(401)
        .json({ message: "email or password is in not in body" });
    }

    const user = await User.findOne({
      email,
    });
    if (!user) {
      return res.status(401).json({
        message: "this user not found , please signUp",
      });
    }
    if (!user.passwordResetVerified) {
      return res.status(403).json({
        message: "Please verify OTP first",
      });
    }
    if (!user.otpExpiry || user.otpExpiry < Date.now()) {
      user.passwordResetVerified = undefined;
      user.otpExpiry = undefined;
      await user.save();
      return res.status(400).json({
        message: "Reset session expired. Request a new OTP.",
      });
    }

    user.password = password;
    user.passwordResetVerified = undefined;
    user.otpExpiry = undefined;
    user.otpAttempts = undefined;

    await user.save();
    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    res.status(400).json({
      message: error,
    });
  }
};
// update password
const updatePassword = async (req, res) => {
  try {
    const { email } = req.user;
    const user = await User.findOne({ email }).select("+password");
    const { currentPassword, newPassword } = req.body;
    const correctPassword = User.isCorrectPassword(
      currentPassword,
      user.password
    );
    if (!correct) {
      return next(new AppError("your currentPassword is incorrect", 400));
    }
    user.password = newPassword;
    user.confirmPassword = confirmNewPassword;
    await user.save();

    res.status(200).json({
      status: "success",
      message: "password changed successfully",
    });
  } catch (error) {
    res.status(400).json({
      status: "failed",
      message: error.message,
    });
  }
};

const filteredObj = (body, ...filtersData) => {
  const obj = {};
  // if(Object.keys(body).includes)
  filtersData.forEach((property) => {
    if (Object.keys(body).includes(property)) {
      return (obj[property] = property);
    }
  });
  return obj;
};
// update me
const updateMe = async (req, res) => {
  try {
    const body = req.body;
    const { id } = req.user;

    if (req.body.passeord) {
      return res.status(400).json({
        status: "failed",
        message: error.message,
      });
    }

    const filterBody = filteredObj(body, "name", "email");

    const newUser = await User.findByIdAndUpdate(id, filterBody, {
      runValidators: true,
      new: true,
    });

    return res.status(200).json({
      status: "success",
      data: newUser,
    });
  } catch (error) {
    return res.status(400).json({
      status: "failed",
      message: error.message,
    });
  }
};
// delete me

const deleteMe = async (req, res) => {
  const { id } = req.user;

  await User.findByIdAndUpdate(id, { active: false });
  res.status(204).json({
    message: "success",
    data: null,
  });
};
export {
  signUp,
  verifyUser,
  requestNewOTP,
  signIn,
  protectRoute,
  forgeetPassword,
  verifyResetPassword,
  resetPassword,
  updatePassword,
  updateMe,
  deleteMe,
};
