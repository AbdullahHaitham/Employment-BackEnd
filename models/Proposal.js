const mongoose = require('mongoose');

const proposalSchema = new mongoose.Schema({
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'FreelanceProject',
    required: true,
  },
  freelancer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  message: { type: String },
  bidAmount: { type: Number },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending',
  }
}, {
  timestamps: true,
});

module.exports = mongoose.model('Proposal', proposalSchema);