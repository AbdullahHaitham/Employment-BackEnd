const User = require('../models/User');
const Company = require('../models/Company');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '1d',
  });
};

// Register
exports.registerUser = async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword, role } = req.body;

    // Validate role
    if (!['user', 'company'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role selected' });
    }

    // Validate passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already registered' });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create user
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      verificationToken,
      role,
      isVerified: role === 'company' ? false : true  // Companies need verification, users are auto-verified in dev
    });

    // Create profile based on role
    if (role === 'user') {
      const newProfile = new UserProfile({
        user: newUser._id,
        headingLine: '',
        summary: '',
        skills: [],
        languages: [],
        experience: [],
        education: []
      });
      await newProfile.save();
      newUser.profile = newProfile._id;
    } else if (role === 'company') {
      // Create empty company profile with default values
      const newCompany = new Company({
        companyName: '',
        registrationNumber: '',
        taxCard: '',
        jobs: []
      });
      await newCompany.save();
      newUser.companyProfile = newCompany._id;
    }

    // Save user
    await newUser.save();

    // Skip email verification in development
    if (process.env.NODE_ENV === 'development') {
      // In development, mark user as verified
      newUser.isVerified = true;
      await newUser.save();
    } else {
      // Send verification email in production
      const verificationLink = `http://localhost:5000/api/auth/verify/${verificationToken}`;
      await sendEmail(
        email,
        'Verify Your Email',
        `Welcome to Employment App! Please verify your email address by clicking the link below:\n\n${verificationLink}\n\nNote: For company accounts, email verification is mandatory for security reasons.`
      );
    }

    res.status(201).json({
      message: 'User registered successfully. Please verify your email.',
      verificationLink: `http://localhost:5000/api/auth/verify/${verificationToken}`
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: {
        message: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      }
    });
  }
};

// Login
exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    if (!user.isVerified) {
      return res.status(401).json({ message: 'Please verify your email first.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

    const token = generateToken(user._id);

    // Set token as cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    // Send response with token and user data
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        isVIP: user.isVIP
      }
    });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// Email Verification
exports.verifyEmail = async (req, res) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully. You can now log in.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};