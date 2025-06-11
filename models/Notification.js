const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    type: {
        type: String,
        enum: ['NEW_JOB', 'APPLICATION_ACCEPTED', 'APPLICATION_REJECTED'],
        required: true
    },
    message: {
        type: String,
        required: true
    },
    jobId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Job',
        required: function() {
            return this.type === 'NEW_JOB' || this.type === 'APPLICATION_ACCEPTED' || this.type === 'APPLICATION_REJECTED';
        }
    },
    applicationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Application',
        required: function() {
            return this.type === 'APPLICATION_ACCEPTED' || this.type === 'APPLICATION_REJECTED';
        }
    },
    isRead: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

const Notification = mongoose.model('Notification', notificationSchema);

module.exports = Notification; 