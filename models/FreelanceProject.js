const mongoose = require('mongoose');

const freelanceProjectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  budget: { type: Number },
  deadline: { type: Date },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('FreelanceProject', freelanceProjectSchema);