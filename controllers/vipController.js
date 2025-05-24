const VIPSubscription = require('../models/VIPSubscription');

exports.createOrRenewSubscription = async (req, res) => {
  try {
    const userId = req.user._id;
    const { durationDays } = req.body; // عدد أيام الاشتراك

    if (!durationDays || durationDays <= 0) {
      return res.status(400).json({ message: 'Invalid subscription duration' });
    }

    let subscription = await VIPSubscription.findOne({ user: userId });

    const now = new Date();
    let newExpiryDate;

    if (subscription && subscription.isActive && subscription.expiryDate > now) {
      newExpiryDate = new Date(subscription.expiryDate);
      newExpiryDate.setDate(newExpiryDate.getDate() + durationDays);
      subscription.expiryDate = newExpiryDate;
    } else {
      newExpiryDate = new Date();
      newExpiryDate.setDate(newExpiryDate.getDate() + durationDays);
      subscription = new VIPSubscription({
        user: userId,
        startDate: now,
        expiryDate: newExpiryDate,
        isActive: true,
      });
    }

    await subscription.save();
    res.json({ message: 'Subscription updated', subscription });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

exports.checkSubscriptionStatus = async (req, res) => {
  try {
    const userId = req.user._id;

    const subscription = await VIPSubscription.findOne({ user: userId });

    if (!subscription || !subscription.isActive || subscription.expiryDate < new Date()) {
      return res.json({ isActive: false });
    }

    res.json({ isActive: true, expiryDate: subscription.expiryDate });

  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};