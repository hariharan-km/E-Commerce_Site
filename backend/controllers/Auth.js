const User = require("../models/User");
const bcrypt = require("bcryptjs");
const { sendMail } = require("../utils/Emails");
const { generateOTP } = require("../utils/GenerateOtp");
const Otp = require("../models/OTP");
const { sanitizeUser } = require("../utils/SanitizeUser");
const { generateToken } = require("../utils/GenerateToken");
const PasswordResetToken = require("../models/PasswordResetToken");

const cookieOptions = {
  sameSite: process.env.PRODUCTION === "true" ? "None" : "Lax",
  httpOnly: true,
  secure: process.env.PRODUCTION === "true",
  maxAge: parseInt(process.env.COOKIE_EXPIRATION_DAYS) * 24 * 60 * 60 * 1000, // days to ms
};

// ✅ Signup Controller
exports.signup = async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    req.body.password = hashedPassword;

    const createdUser = new User(req.body);
    await createdUser.save();

    const secureInfo = sanitizeUser(createdUser);
    const token = generateToken(secureInfo);

    res.cookie("token", token, cookieOptions);
    res.status(201).json(secureInfo);
  } catch (error) {
    console.error("Signup Error:", error);
    res.status(500).json({ message: "Error occurred during signup" });
  }
};

// ✅ Login Controller
exports.login = async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });

    if (existingUser && (await bcrypt.compare(req.body.password, existingUser.password))) {
      const secureInfo = sanitizeUser(existingUser);
      const token = generateToken(secureInfo);

      res.cookie("token", token, cookieOptions);
      return res.status(200).json(secureInfo);
    }

    res.clearCookie("token");
    return res.status(401).json({ message: "Invalid Credentials" });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Login error. Please try again." });
  }
};

// ✅ Verify OTP
exports.verifyOtp = async (req, res) => {
  try {
    const user = await User.findById(req.body.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const otpRecord = await Otp.findOne({ user: user._id });
    if (!otpRecord) return res.status(404).json({ message: "OTP not found" });

    if (otpRecord.expiresAt < Date.now()) {
      await Otp.findByIdAndDelete(otpRecord._id);
      return res.status(400).json({ message: "OTP has expired" });
    }

    const isValidOtp = await bcrypt.compare(req.body.otp, otpRecord.otp);
    if (!isValidOtp) return res.status(400).json({ message: "Invalid OTP" });

    await Otp.findByIdAndDelete(otpRecord._id);
    const verifiedUser = await User.findByIdAndUpdate(user._id, { isVerified: true }, { new: true });
    res.status(200).json(sanitizeUser(verifiedUser));
  } catch (error) {
    console.error("OTP Verification Error:", error);
    res.status(500).json({ message: "OTP verification failed" });
  }
};

// ✅ Resend OTP
exports.resendOtp = async (req, res) => {
  try {
    const user = await User.findById(req.body.user);
    if (!user) return res.status(404).json({ message: "User not found" });

    await Otp.deleteMany({ user: user._id });

    const otp = generateOTP();
    const hashedOtp = await bcrypt.hash(otp, 10);

    const newOtp = new Otp({
      user: user._id,
      otp: hashedOtp,
      expiresAt: Date.now() + parseInt(process.env.OTP_EXPIRATION_TIME),
    });

    await newOtp.save();

    await sendMail(
      user.email,
      "OTP Verification for Your Account",
      `Your OTP is: <b>${otp}</b><br>This OTP is valid for 5 minutes.`
    );

    res.status(201).json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("Resend OTP Error:", error);
    res.status(500).json({ message: "Error resending OTP" });
  }
};

// ✅ Forgot Password
exports.forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).json({ message: "Email not registered" });

    await PasswordResetToken.deleteMany({ user: user._id });

    const resetToken = generateToken(sanitizeUser(user), true);
    const hashedToken = await bcrypt.hash(resetToken, 10);

    const newResetToken = new PasswordResetToken({
      user: user._id,
      token: hashedToken,
      expiresAt: Date.now() + parseInt(process.env.OTP_EXPIRATION_TIME),
    });

    await newResetToken.save();

    const resetLink = `${process.env.ORIGIN}/reset-password/${user._id}/${resetToken}`;

    await sendMail(
      user.email,
      "Password Reset Link",
      `<p>Hello ${user.name},</p>
       <p>Click <a href="${resetLink}">here</a> to reset your password. The link is valid for 5 minutes.</p>`
    );

    res.status(200).json({ message: `Password reset link sent to ${user.email}` });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ message: "Error sending reset link" });
  }
};

// ✅ Reset Password
exports.resetPassword = async (req, res) => {
  try {
    const user = await User.findById(req.body.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const tokenDoc = await PasswordResetToken.findOne({ user: user._id });
    if (!tokenDoc || tokenDoc.expiresAt < Date.now()) {
      if (tokenDoc) await PasswordResetToken.findByIdAndDelete(tokenDoc._id);
      return res.status(400).json({ message: "Reset link expired or invalid" });
    }

    const isValid = await bcrypt.compare(req.body.token, tokenDoc.token);
    if (!isValid) return res.status(400).json({ message: "Invalid reset token" });

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.findByIdAndUpdate(user._id, { password: hashedPassword });
    await PasswordResetToken.findByIdAndDelete(tokenDoc._id);

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({ message: "Error resetting password" });
  }
};

// ✅ Logout
exports.logout = async (req, res) => {
  try {
    res.cookie("token", "", {
      ...cookieOptions,
      maxAge: 0,
    });
    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout Error:", error);
    res.status(500).json({ message: "Logout failed" });
  }
};

// ✅ Auth Check
exports.checkAuth = async (req, res) => {
  try {
    if (!req.user) return res.sendStatus(401);

    const user = await User.findById(req.user._id);
    res.status(200).json(sanitizeUser(user));
  } catch (error) {
    console.error("Check Auth Error:", error);
    res.sendStatus(500);
  }
};
