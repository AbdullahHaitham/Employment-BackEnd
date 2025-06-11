const express = require('express');
const router = express.Router();
const companyController = require('../controllers/companyController');

// Company routes
router.post('/', companyController.createCompany);
router.get('/', companyController.getAllCompanies);
router.get('/:id', companyController.getCompanyById);
router.put('/:id', companyController.updateCompany);
router.delete('/:id', companyController.deleteCompany);

// Job posting routes for companies
router.post('/:id/jobs', companyController.postJob);
router.get('/:id/jobs', companyController.getCompanyJobs);

module.exports = router; 