import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  // confirmPassword:{ type: String, required: true},
  isAdmin: { type: Boolean, default: false },
  resetOTP: String,
  otpExpiry: Date,
});

export default mongoose.model('User', userSchema);