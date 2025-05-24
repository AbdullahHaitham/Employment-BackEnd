const Job = require('../models/Job');

// Create job
exports.createJob = async (req, res) => {
  try {
    const { title, description, company, location, salary } = req.body;

    const job = new Job({
      title,
      description,
      company,
      location,
      salary,
      createdBy: req.user._id, 
    });

    await job.save();
    res.status(201).json(job);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// Get all jobs
exports.getJobs = async (req, res) => {
  try {
    const jobs = await Job.find().populate('createdBy', 'fullName email');
    res.json(jobs);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};