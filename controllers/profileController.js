const UserProfile = require('../models/UserProfile');
const Company = require('../models/Company');
const User = require('../models/User');
const upload = require('../config/multer');

// Upload CV
exports.uploadCV = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Please upload a CV file' });
    }

    const profile = await UserProfile.findOne({ user: req.user._id });
    if (!profile) {
      return res.status(404).json({ message: 'Profile not found' });
    }

    // Update CV path
    profile.cv = `/uploads/cv/${req.file.filename}`;
    await profile.save();

    res.json({ message: 'CV uploaded successfully', cv: profile.cv });
  } catch (error) {
    console.error('CV upload error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Get current user's profile
exports.getProfile = async (req, res) => {
  try {
    if (req.user.role === 'user') {
      const profile = await UserProfile.findOne({ user: req.user._id });
      if (!profile) {
        return res.status(404).json({ message: 'Profile not found' });
      }
      res.json(profile);
    } else {
      const company = await Company.findOne({ _id: req.user.companyProfile });
      if (!company) {
        return res.status(404).json({ message: 'Company profile not found' });
      }
      res.json(company);
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Update user profile
exports.updateProfile = async (req, res) => {
  try {
    if (req.user.role === 'user') {
      let profile = await UserProfile.findOne({ user: req.user._id });
      
      if (!profile) {
        // Create new profile if it doesn't exist
        profile = new UserProfile({
          user: req.user._id
        });
        req.user.profile = profile._id;
        await req.user.save();
      }

      // Update all fields
      const updateFields = ['headingLine', 'summary'];
      updateFields.forEach(field => {
        if (req.body[field] !== undefined) {
          profile[field] = req.body[field];
        }
      });

      // Handle skills
      if (req.body.skills) {
        profile.skills = req.body.skills;
      }

      // Handle languages
      if (req.body.languages) {
        profile.languages = req.body.languages;
      }

      // Handle experience
      if (req.body.experience) {
        profile.experience = req.body.experience.map(exp => ({
          title: exp.title,
          company: exp.company,
          location: exp.location,
          from: new Date(exp.from),
          to: exp.to ? new Date(exp.to) : undefined,
          current: exp.current || false,
          description: exp.description
        }));
      }

      await profile.save();
      res.json(profile);
    } else {
      // Handle company profile update
      const company = await Company.findById(req.user.companyProfile);
      if (!company) {
        return res.status(404).json({ message: 'Company profile not found' });
      }

      const { companyName, registrationNumber, taxCard } = req.body;
      Object.assign(company, { companyName, registrationNumber, taxCard });
      await company.save();
      res.json(company);
    }
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Get current user's profile
exports.getProfile = async (req, res) => {
  try {
    if (req.user.role === 'user') {
      const profile = await UserProfile.findOne({ user: req.user._id });
      if (!profile) {
        return res.status(404).json({ message: 'Profile not found' });
      }
      res.json(profile);
    } else {
      const company = await Company.findOne({ _id: req.user.companyProfile });
      if (!company) {
        return res.status(404).json({ message: 'Company profile not found' });
      }
      res.json(company);
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Update user profile
exports.updateProfile = async (req, res) => {
  try {
    if (req.user.role === 'user') {
      let profile = await UserProfile.findOne({ user: req.user._id });
      
      if (!profile) {
        // Create new profile if it doesn't exist
        profile = new UserProfile({
          user: req.user._id
        });
        req.user.profile = profile._id;
        await req.user.save();
      }

      // Update all fields
      const updateFields = ['headingLine', 'summary'];
      updateFields.forEach(field => {
        if (req.body[field] !== undefined) {
          profile[field] = req.body[field];
        }
      });

      // Handle skills
      if (req.body.skills) {
        profile.skills = req.body.skills;
      }

      // Handle languages
      if (req.body.languages) {
        profile.languages = req.body.languages;
      }

      // Handle experience
      if (req.body.experience) {
        profile.experience = req.body.experience.map(exp => ({
          title: exp.title,
          company: exp.company,
          location: exp.location,
          from: new Date(exp.from),
          to: exp.to ? new Date(exp.to) : undefined,
          current: exp.current || false,
          description: exp.description
        }));
      }

      await profile.save();
      res.json(profile);
    } else {
      // Handle company profile update
      const company = await Company.findById(req.user.companyProfile);
      if (!company) {
        return res.status(404).json({ message: 'Company profile not found' });
      }

      const { companyName, registrationNumber, taxCard } = req.body;
      Object.assign(company, { companyName, registrationNumber, taxCard });
      await company.save();
      res.json(company);
    }
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Get current user's profile
exports.getProfile = async (req, res) => {
  try {
    if (req.user.role === 'user') {
      const profile = await UserProfile.findOne({ user: req.user._id });
      if (!profile) {
        return res.status(404).json({ message: 'Profile not found' });
      }
      res.json(profile);
    } else {
      const company = await Company.findOne({ _id: req.user.companyProfile });
      if (!company) {
        return res.status(404).json({ message: 'Company profile not found' });
      }
      res.json(company);
    }
  } catch (error) {
    console.error('Profile get error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Upload CV
exports.uploadCV = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Please upload a file' });
    }

    const profile = await UserProfile.findOne({ user: req.user._id });
    if (!profile) {
      return res.status(404).json({ message: 'Profile not found' });
    }

    profile.cv = req.file.path;
    await profile.save();

    res.json({ message: 'CV uploaded successfully', cv: profile.cv });
  } catch (error) {
    console.error('CV upload error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Upload CV
exports.uploadCV = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Please upload a file' });
    }

    const profile = await UserProfile.findOne({ user: req.user._id });
    if (!profile) {
      return res.status(404).json({ message: 'Profile not found' });
    }

    profile.cv = req.file.path;
    await profile.save();

    res.json({ message: 'CV uploaded successfully', cv: profile.cv });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};