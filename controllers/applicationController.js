const Application = require('../models/Application');

// تقديم على وظيفة
exports.applyToJob = async (req, res) => {
  try {
    const { jobId, coverLetter } = req.body;

    const application = new Application({
      job: jobId,
      applicant: req.user._id,
      coverLetter,
    });

    await application.save();
    res.status(201).json({ message: 'Applied successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

exports.getMyApplications = async (req, res) => {
  try {
    const apps = await Application.find({ applicant: req.user._id }).populate('job');
    res.json(apps);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};