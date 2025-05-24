const Proposal = require('../models/Proposal');

// تقديم عرض
exports.sendProposal = async (req, res) => {
  try {
    const { projectId, message, bidAmount } = req.body;

    const proposal = new Proposal({
      project: projectId,
      freelancer: req.user._id,
      message,
      bidAmount,
    });

    await proposal.save();
    res.status(201).json({ message: 'Proposal sent' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// عرض كل العروض اللي بعتها المستخدم
exports.getMyProposals = async (req, res) => {
  try {
    const proposals = await Proposal.find({ freelancer: req.user._id }).populate('project');
    res.json(proposals);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};