import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { generateOTP } from '../utils/generateOTP.js';
import { sendEmail } from '../utils/sendEmail.js';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '1d';

export const signup = async (req, res) => {
  try {
    const { username, email, password, confirmPassword, isAdmin } = req.body;
    if (password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match.' });

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(400).json({ message: 'User already exists.' });

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ username, email, password: hashed, isAdmin });
    await user.save();
    res.status(201).json({ message: 'Signup successful.' });
  } catch (err) {
    console.log(err);
    
    res.status(500).json({ message: 'Server error.' });
  }
};

export const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Invalid credentials.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ token, user: { id: user._id, username: user.username, isAdmin: user.isAdmin } });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const otp = generateOTP();
    user.resetOTP = otp;
    user.otpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    await sendEmail(email, 'Your OTP for Password Reset', `<h2>Your OTP is: ${otp}</h2>`);
    res.json({ message: 'OTP sent to email.' });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Server error.' });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword, confirmPassword } = req.body;
    if (newPassword !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match.' });

    const user = await User.findOne({ email, resetOTP: otp, otpExpiry: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ message: 'Invalid or expired OTP.' });

    user.password = await bcrypt.hash(newPassword, 12);
    user.resetOTP = undefined;
    user.otpExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
};