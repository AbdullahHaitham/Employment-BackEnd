const express = require('express');
const router = express.Router();
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');
const VIPSubscription = require('../models/VIPSubscription');

// Webhook Route
router.post('/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    // Stripe uses raw body for verification, this will fail if body was parsed as JSON
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('❌ Webhook Error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // ✅ Checkout session completed → User paid successfully
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const customerEmail = session.customer_email;
    const userId = session.metadata.userId;
    try {
      // First try to find user by Stripe customer ID
      const user = await User.findOne({ stripeCustomerId: session.customer });
      
      if (user) {
        user.isVIP = true;
        await user.save();
        
        // Create or update VIPSubscription
        const now = new Date();
        const expiryDate = new Date(now.getTime() + (30 * 24 * 60 * 60 * 1000)); // 30 days from now
        
        const subscription = await VIPSubscription.findOne({ user: user._id });
        if (subscription) {
          subscription.expiryDate = expiryDate;
          subscription.isActive = true;
          await subscription.save();
        } else {
          const newSubscription = new VIPSubscription({
            user: user._id,
            startDate: now,
            expiryDate,
            isActive: true
          });
          await newSubscription.save();
        }
        
        console.log(`✅ ${user.email} is now VIP`);
      } else {
        console.warn(`⚠️ User with Stripe customer ID ${session.customer} not found`);
        // As a fallback, try to find user by email
        const userEmailUser = await User.findOne({ email: customerEmail });
        if (userEmailUser) {
          userEmailUser.isVIP = true;
          await userEmailUser.save();
          console.log(`✅ ${userEmailUser.email} is now VIP (found by email)`);
        } else {
          console.warn(`⚠️ User with email ${customerEmail} not found`);
        }
      }
    } catch (err) {
      console.error('❌ Database Error:', err);
    }
  }

  res.status(200).json({ received: true });
});

module.exports = router;