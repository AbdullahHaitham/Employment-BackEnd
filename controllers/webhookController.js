const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');
const VIPSubscription = require('../models/VIPSubscription');

exports.handleWebhook = async (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    switch (event.type) {
        case 'checkout.session.completed':
            const session = event.data.object;
            const userId = session.metadata.userId;
            
            try {
                // Update user's VIP status
                await User.findByIdAndUpdate(userId, { isVIP: true });
                
                // Create or update VIP subscription
                let subscription = await VIPSubscription.findOne({ user: userId });
                if (!subscription) {
                    subscription = new VIPSubscription({
                        user: userId,
                        startDate: new Date(),
                        expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
                        isActive: true
                    });
                } else {
                    subscription.isActive = true;
                    subscription.expiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
                }
                await subscription.save();
                
                res.json({ received: true });
            } catch (error) {
                console.error('Error updating subscription:', error);
                res.status(500).send('Error updating subscription');
            }
            break;

        case 'customer.subscription.deleted':
            const subscription = event.data.object;
            const customerId = subscription.customer;
            
            try {
                // Find user by customer ID
                const user = await User.findOne({ stripeCustomerId: customerId });
                if (user) {
                    user.isVIP = false;
                    await user.save();
                }
                
                // Update subscription status
                const vipSub = await VIPSubscription.findOne({ user: user._id });
                if (vipSub) {
                    vipSub.isActive = false;
                    await vipSub.save();
                }
                
                res.json({ received: true });
            } catch (error) {
                console.error('Error updating subscription:', error);
                res.status(500).send('Error updating subscription');
            }
            break;

        default:
            res.json({ received: true });
    }
};