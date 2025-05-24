const express = require('express');
const router = express.Router();
const { createCheckoutSession } = require('../controllers/paymentController');
const protect = require('../middleware/authMiddleware'); 

router.post('/stripe', protect, createCheckoutSession);
module.exports = router;