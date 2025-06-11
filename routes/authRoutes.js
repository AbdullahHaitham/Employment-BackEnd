const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
router.use(cookieParser());

// Cookie options for secure storage
const cookieOptions = {
  httpOnly: true,      // Prevents client-side JavaScript from accessing the cookie
  secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
  sameSite: 'strict',  // Prevents CSRF attacks
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
};

const {
  registerUser,
  loginUser,
  verifyEmail
} = require('../controllers/authController');

// Authentication middleware
const protect = async (req, res, next) => {
  try {
    // Get token from cookie
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: 'Not authorized to access this route' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    next();
  } catch (error) {
    res.status(401).json({ message: 'Not authorized to access this route' });
  }
};
const { upload, ensureUploadDir } = require('../middleware/uploadMiddleware');
const User = require('../models/User');

// Register
router.post('/register', registerUser);

// Login route is handled by the imported loginUser function
router.post('/login', loginUser);

// Email Verification
router.get('/verify/:token', verifyEmail);

// Upload CV
router.post('/upload-cv', protect, ensureUploadDir, upload.single('cv'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const user = await User.findById(req.user._id);
    user.cv = req.file.filename;
    await user.save();

    res.json({ message: 'CV uploaded successfully', filename: req.file.filename });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Forgot Password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Validate email format
    if (!email || !email.includes('@')) {
      return res.status(400).json({ message: 'Please provide a valid email address' });
    }

    const user = await User.findOne({ email });
    
    if (!user) {
      // Don't reveal if email exists for security
      return res.status(200).json({ message: 'If an account exists with this email, you will receive a password reset email' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = Date.now() + 3600000; // 1 hour

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetExpires;
    user.passwordResetVerified = false;
    await user.save();

    // Send reset email
    const resetUrl = `http://localhost:5000/api/auth/reset-password/${resetToken}`;
    
    try {
      await sendEmail(
        user.email,
        'Password Reset Request',
        `You have requested a password reset. Please click the link below to reset your password:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email.`
      );
      
      // Include the reset link in the response
      res.status(200).json({ 
        message: 'Password reset link generated successfully',
        resetLink: resetUrl
      });
    } catch (emailError) {
      // Clear the reset token if email fails
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();
      
      console.error('Email sending failed:', emailError);
      res.status(500).json({ 
        message: 'Failed to send password reset email. Please try again later.',
        error: emailError.message
      });
    }
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ message: 'An error occurred. Please try again later.' });
  }
});

// Reset Password
router.post('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Update user
    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordResetVerified = true;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password', error });
  }
});

// Profile
router.get('/profile', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ✅ Manual VIP Activation After Payment
router.post('/vip/activate', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.isVIP = true;
    await user.save();

    res.json({ message: 'VIP activated successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;