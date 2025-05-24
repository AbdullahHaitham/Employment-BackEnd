const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const connectDB = require('./config/db');
const path = require('path');
const bodyParser = require('body-parser');

// Load environment variables
const envPath = path.join(__dirname, '.env');
dotenv.config({ path: envPath });

// Debug logging - check if environment variables are loaded
console.log('Environment Variables:');
console.log('PORT:', process.env.PORT);
console.log('MONGO_URI:', process.env.MONGO_URI);
console.log('JWT_SECRET:', process.env.JWT_SECRET);
console.log('STRIPE_SECRET_KEY:', process.env.STRIPE_SECRET_KEY);
console.log('STRIPE_PUBLISHABLE_KEY:', process.env.STRIPE_PUBLISHABLE_KEY);

connectDB();

const app = express();

// Middleware
app.use(cors());

//  Webhook route must use raw body parser BEFORE express.json
app.use('/api/webhook/stripe', bodyParser.raw({ type: 'application/json' }));

// JSON parser for other routes
app.use(express.json());

// Routes
app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/jobs', require('./routes/jobRoutes'));
app.use('/api/applications', require('./routes/applicationRoutes'));
app.use('/api/freelance', require('./routes/freelanceRoutes'));
app.use('/api/proposals', require('./routes/proposalRoutes'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/api/vip', require('./routes/vipRoutes'));
app.use('/api/webhook', require('./routes/webhookRoutes'));
app.use('/api/payment', require('./routes/paymentRoutes')); 

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));