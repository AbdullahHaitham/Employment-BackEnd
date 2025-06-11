const Notification = require('../models/Notification');
const User = require('../models/User');
const Job = require('../models/Job');
const Application = require('../models/Application');

// Utility function to create a notification
const createNotification = async (userId, type, message, jobId = null, applicationId = null) => {
    try {
        const notification = new Notification({
            userId,
            type,
            message,
            jobId,
            applicationId
        });
        await notification.save();
        return notification;
    } catch (error) {
        console.error('Error creating notification:', error);
        throw error;
    }
};

// Create notification for new job
exports.notifyNewJob = async (jobId) => {
    try {
        const job = await Job.findById(jobId).populate('company');
        if (!job) throw new Error('Job not found');

        // Get all users who might be interested in the job
        const users = await User.find({ role: 'jobseeker' });
        
        const notifications = users.map(user => 
            createNotification(
                user._id,
                'NEW_JOB',
                `New job posted: ${job.title} at ${job.company.name}`,
                jobId
            )
        );

        await Promise.all(notifications);
    } catch (error) {
        console.error('Error notifying new job:', error);
        throw error;
    }
};

// Create notification for application status change
exports.notifyApplicationStatus = async (applicationId, status) => {
    try {
        const application = await Application.findById(applicationId)
            .populate('job')
            .populate('user')
            .populate({
                path: 'job',
                populate: {
                    path: 'company'
                }
            });

        if (!application) throw new Error('Application not found');

        const type = status === 'accepted' ? 'APPLICATION_ACCEPTED' : 'APPLICATION_REJECTED';
        const message = status === 'accepted'
            ? `Dear ${application.user.firstName}, we are happy to tell you that your application has been accepted to the job you apply for, ${application.job.company.name}`
            : `Dear ${application.user.firstName}, we are sad to tell you that your application has been rejected to the job you apply for, ${application.job.company.name}`;

        await createNotification(
            application.user._id,
            type,
            message,
            application.job._id,
            applicationId
        );
    } catch (error) {
        console.error('Error notifying application status:', error);
        throw error;
    }
};

// Get all notifications for a user
exports.getUserNotifications = async (req, res) => {
    try {
        const notifications = await Notification.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .populate('jobId')
            .populate('applicationId');

        res.status(200).json({
            success: true,
            count: notifications.length,
            data: notifications
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
};

// Mark notification as read
exports.markAsRead = async (req, res) => {
    try {
        const notification = await Notification.findById(req.params.id);
        
        if (!notification) {
            return res.status(404).json({
                success: false,
                message: 'Notification not found'
            });
        }

        if (notification.userId.toString() !== req.user._id.toString()) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized to update this notification'
            });
        }

        notification.isRead = true;
        await notification.save();

        res.status(200).json({
            success: true,
            data: notification
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
};

// Mark all notifications as read
exports.markAllAsRead = async (req, res) => {
    try {
        await Notification.updateMany(
            { userId: req.user._id, isRead: false },
            { isRead: true }
        );

        res.status(200).json({
            success: true,
            message: 'All notifications marked as read'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
};

// Delete a notification
exports.deleteNotification = async (req, res) => {
    try {
        const notification = await Notification.findById(req.params.id);
        
        if (!notification) {
            return res.status(404).json({
                success: false,
                message: 'Notification not found'
            });
        }

        if (notification.userId.toString() !== req.user._id.toString()) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized to delete this notification'
            });
        }

        await notification.remove();

        res.status(200).json({
            success: true,
            message: 'Notification deleted successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
}; 