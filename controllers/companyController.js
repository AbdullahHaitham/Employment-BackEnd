const Company = require('../models/Company');
const Job = require('../models/Job');

// Create a new company
exports.createCompany = async (req, res) => {
    try {
        const company = new Company(req.body);
        await company.save();
        res.status(201).json(company);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

// Get all companies
exports.getAllCompanies = async (req, res) => {
    try {
        const companies = await Company.find().populate('jobs');
        res.json(companies);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Get company by ID
exports.getCompanyById = async (req, res) => {
    try {
        const company = await Company.findById(req.params.id).populate('jobs');
        if (!company) {
            return res.status(404).json({ error: 'Company not found' });
        }
        res.json(company);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Update company
exports.updateCompany = async (req, res) => {
    try {
        const company = await Company.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        );
        if (!company) {
            return res.status(404).json({ error: 'Company not found' });
        }
        res.json(company);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

// Delete company
exports.deleteCompany = async (req, res) => {
    try {
        const company = await Company.findByIdAndDelete(req.params.id);
        if (!company) {
            return res.status(404).json({ error: 'Company not found' });
        }
        res.json({ message: 'Company deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Post a new job for a company
exports.postJob = async (req, res) => {
    try {
        const company = await Company.findById(req.params.id);
        if (!company) {
            return res.status(404).json({ error: 'Company not found' });
        }

        // Create new job with company reference
        const job = new Job({
            ...req.body,
            company: company._id,
            companyName: company.companyName // Add company name to job for easier reference
        });

        // Save the job
        await job.save();

        // Add job reference to company's jobs array
        company.jobs.push(job._id);
        await company.save();

        // Return the job with populated company details
        const populatedJob = await Job.findById(job._id).populate('company', 'companyName registrationNumber');
        res.status(201).json(populatedJob);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

// Get all jobs for a company
exports.getCompanyJobs = async (req, res) => {
    try {
        const company = await Company.findById(req.params.id);
        if (!company) {
            return res.status(404).json({ error: 'Company not found' });
        }

        // Find all jobs associated with this company
        const jobs = await Job.find({ company: company._id })
            .populate('company', 'companyName registrationNumber');
        
        res.json(jobs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}; 