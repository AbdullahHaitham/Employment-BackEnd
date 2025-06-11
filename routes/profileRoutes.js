const express = require('express');
const router = express.Router();
const { getProfile, updateProfile, uploadCV } = require('../controllers/profileController');
const protect = require('../middleware/authMiddleware');
const upload = require('../config/multer');

router.get('/', protect, getProfile);
router.put('/', protect, updateProfile);
router.post('/upload-cv', protect, upload.single('cv'), uploadCV);

module.exports = router;