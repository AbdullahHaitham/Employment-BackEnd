const express = require('express');
const router = express.Router();
const { sendProposal, getMyProposals } = require('../controllers/proposalController');
const protect = require('../middleware/authMiddleware');

router.post('/send', protect, sendProposal);
router.get('/my-proposals', protect, getMyProposals);

module.exports = router;