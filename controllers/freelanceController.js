const FreelanceProject = require('../models/FreelanceProject');

// إنشاء مشروع حر
exports.createProject = async (req, res) => {
  try {
    const { title, description, budget, deadline } = req.body;

    const project = new FreelanceProject({
      title,
      description,
      budget,
      deadline,
      createdBy: req.user._id,
    });

    await project.save();
    res.status(201).json(project);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// عرض كل المشاريع
exports.getProjects = async (req, res) => {
  try {
    const projects = await FreelanceProject.find().populate('createdBy', 'fullName email');
    res.json(projects);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};