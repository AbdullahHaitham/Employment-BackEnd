const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');

exports.createCheckoutSession = async (req, res) => {
  try {
    // First, check if user has a Stripe customer ID
    const user = await User.findById(req.user._id);
    let customer;
    
    if (!user.stripeCustomerId) {
      // Create a new Stripe customer if they don't have one
      customer = await stripe.customers.create({
        email: req.user.email,
        metadata: {
          userId: req.user._id.toString()
        }
      });
      
      // Update user's Stripe customer ID in your database
      user.stripeCustomerId = customer.id;
      await user.save();
    } else {
      customer = await stripe.customers.retrieve(user.stripeCustomerId);
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: 'VIP Subscription',
            },
            unit_amount: 500,
          },
          quantity: 1,
        },
      ],
      customer: customer.id, // Use the customer ID instead of email
      metadata: {
        userId: req.user._id.toString(), 
      },
      success_url: 'http://localhost:3000/payment-success',
      cancel_url: 'http://localhost:3000/payment-cancel',
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error('Stripe Checkout Error:', error);
    res.status(500).json({ message: 'Failed to create Stripe session', error: error.message });
  }
};