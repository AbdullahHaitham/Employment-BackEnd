const express = require('express');
const router = express.Router();
const protect = require('../middleware/authMiddleware');
const { createOrRenewSubscription, checkSubscriptionStatus } = require('../controllers/vipController');

router.post('/subscribe', protect, createOrRenewSubscription);
router.get('/status', protect, checkSubscriptionStatus);

module.exports = router;