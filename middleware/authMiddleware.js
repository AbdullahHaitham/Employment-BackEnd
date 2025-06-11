const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  try {
    // Try to get token from cookie first
    let token = req.cookies.token;
    console.log('Token from cookie:', token);

    // If no cookie token, try to get from header
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
      console.log('Token from header:', token);
    }

    if (!token) {
      console.log('No token found in request');
      return res.status(401).json({ message: 'Not authorized, no token' });
    }

    console.log('Token received:', token);
    
    // Verify token
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('Decoded token:', decoded);
      
      if (!decoded.id) {
        console.log('No id in decoded token');
        return res.status(401).json({ message: 'Invalid token format' });
      }

      req.user = await User.findById(decoded.id).select('-password');
      if (!req.user) {
        console.log('User not found for id:', decoded.id);
        return res.status(401).json({ message: 'User not found' });
      }
      
      next();
    } catch (verifyError) {
      console.error('Token verification error:', verifyError);
      return res.status(401).json({ 
        message: 'Not authorized, token failed',
        error: verifyError.message
      });
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({ 
      message: 'Not authorized, token failed',
      error: error.message
    });
  }
};

module.exports = protect;