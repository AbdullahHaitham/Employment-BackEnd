const mongoose = require('mongoose');

const userProfileSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  headingLine: {
    type: String,
    trim: true
  },
  summary: {
    type: String,
    trim: true
  },
  skills: {
    type: [String],
    default: []
  },
  languages: {
    type: [String],
    default: []
  },
  experience: [{
    title: {
      type: String,
      required: true,
      trim: true
    },
    company: {
      type: String,
      required: true,
      trim: true
    },
    location: {
      type: String,
      trim: true
    },
    from: {
      type: Date,
      required: true
    },
    to: {
      type: Date
    },
    current: {
      type: Boolean,
      default: false
    },
    description: {
      type: String,
      trim: true
    }
  }],
  industry: {
    type: String,
    trim: true
  },
  cv: {
    type: String
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('UserProfile', userProfileSchema);