const mongoose = require('mongoose');

const companySchema = new mongoose.Schema({
    companyName: {
        type: String,
        trim: true,
        default: ''
    },
    registrationNumber: {
        type: String,
        trim: true,
        default: ''
    },
    taxCard: {
        type: String,
        trim: true,
        default: ''
    },
    jobs: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Job'
    }]
}, {
    timestamps: true
});

module.exports = mongoose.model('Company', companySchema);