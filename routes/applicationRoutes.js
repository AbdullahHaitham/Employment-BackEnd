const express = require('express');
const router = express.Router();
const { applyToJob, getMyApplications } = require('../controllers/applicationController');
const protect = require('../middleware/authMiddleware');

router.post('/apply', protect, applyToJob);
router.get('/my-applications', protect, getMyApplications);

module.exports = router;