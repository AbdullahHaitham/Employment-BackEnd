# Employment Backend

A full-featured employment management system backend built with Node.js and Express.

## Features

- User Authentication (Signup/Login)
- Profile Management
- Job Posting System
- Company Management
- Notification System
- File Upload (CVs, Documents)
- Payment Integration (Stripe)

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **Authentication**: JWT
- **File Upload**: Multer
- **Email**: Nodemailer with SendGrid
- **Payment**: Stripe

## Database Schema

### User Profile Schema
```javascript
UserProfile {
  user: {
    type: ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  headingLine: String,
  summary: String,
  skills: [String],
  languages: [String],
  experience: [{
    title: String,
    company: String,
    startDate: Date,
    endDate: Date,
    description: String
  }],
  education: [{
    institution: String,
    degree: String,
    fieldOfStudy: String,
    startDate: Date,
    endDate: Date
  }],
  cv: {
    filename: String,
    path: String,
    uploadDate: Date
  }
}
```

### Company Profile Schema
```javascript
Company {
  user: {
    type: ObjectId,
    ref: 'User',
    required: true
  },
  companyName: String,
  registrationNumber: String,
  taxCard: String,
  description: String,
  website: String,
  logo: {
    filename: String,
    path: String,
    uploadDate: Date
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  contact: {
    email: String,
    phone: String,
    socialLinks: {
      linkedin: String,
      twitter: String,
      facebook: String
    }
  },
  jobs: [{
    type: ObjectId,
    ref: 'Job'
  }]
}
```

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB
- Stripe Account
- SendGrid Account

### Installation

1. Clone the repository:
```bash
git clone https://github.com/AbdullahHaitham/Employment-BackEnd.git
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
Create a `.env` file in the root directory with the following variables:
```
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
STRIPE_SECRET_KEY=your_stripe_secret_key
SENDGRID_API_KEY=your_sendgrid_api_key
```

4. Start the server:
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## Project Structure

```
employment-backend/
├── config/           # Configuration files
│   └── multer.js     # File upload configuration
├── controllers/      # Route controllers
│   ├── authController.js
│   ├── profileController.js
│   ├── companyController.js
│   ├── notificationController.js
│   └── ...other controllers
├── middleware/       # Custom middleware
│   └── authMiddleware.js
├── models/          # Database models
│   ├── User.js
│   ├── Company.js
│   ├── UserProfile.js
│   ├── Job.js
│   ├── FreelanceProject.js
│   ├── Application.js
│   ├── Proposal.js
│   ├── Notification.js
│   └── VIPSubscription.js
├── routes/          # API routes
│   ├── authRoutes.js
│   ├── profileRoutes.js
│   ├── companyRoutes.js
│   ├── notificationRoutes.js
│   └── ...other routes
├── uploads/         # Uploaded files storage
├── utils/          # Utility functions
├── server.js        # Main application file
└── package.json     # Project dependencies
```

## API Endpoints

### Authentication
- POST `/api/auth/register` - Register new user
- POST `/api/auth/login` - User login
- POST `/api/auth/logout` - User logout
- POST `/api/auth/verify-email` - Verify user email

### Profile Management
- GET `/api/profile` - Get user profile
- PUT `/api/profile` - Update profile
- POST `/api/profile/upload-cv` - Upload CV

### Company Management
- POST `/api/companies` - Create company
- GET `/api/companies` - Get all companies
- GET `/api/companies/:id` - Get company details
- PUT `/api/companies/:id` - Update company
- DELETE `/api/companies/:id` - Delete company
- POST `/api/companies/:id/jobs` - Post job for company
- GET `/api/companies/:id/jobs` - Get company's jobs

### Job Management
- POST `/api/jobs` - Create job posting
- GET `/api/jobs` - Get all job postings

### Freelance Project Management
- POST `/api/freelance` - Create freelance project
- GET `/api/freelance` - Get all freelance projects

### Payment & Subscription
- POST `/api/payment/stripe` - Create Stripe checkout session
- POST `/api/vip` - Subscribe to VIP plan

### Applications & Proposals
- POST `/api/applications` - Submit job application
- POST `/api/proposals` - Submit project proposal

### Notifications
- POST `/api/notifications` - Create notification
- GET `/api/notifications` - Get user notifications

### Webhook Integration
- POST `/api/webhook/stripe` - Handle Stripe webhook events
- POST `/api/webhook/sendgrid` - Handle SendGrid webhook events

### Documentation Notes

- All endpoints except `/api/auth/register` and `/api/auth/login` require authentication
- Use `Bearer` token in Authorization header for authenticated requests
- Response format is consistent across endpoints:
  - Success: `{ status: 'success', data: {...} }`
  - Error: `{ status: 'error', message: 'Error message' }`

### API Versioning
- Current version: v1
- Base URL: `https://your-domain.com/api/v1/` (in production)
- Local development: `http://localhost:5000/api/v1/`

### VIP Features
- POST `/api/vip` - Subscribe to VIP plan
- GET `/api/vip/status` - Check VIP status

## Environment Variables
Create a `.env` file with the following variables:
```
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
SENDGRID_API_KEY=your_sendgrid_api_key
STRIPE_SECRET_KEY=your_stripe_secret_key
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_email_password_or_app_password
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret
```

## Setup and Installation
1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file with required environment variables
4. Start the server:
   ```bash
   npm run dev   # Development mode with nodemon
   npm start     # Production mode
   ```

## Security Features
- JWT-based authentication
- Password hashing using bcrypt
- CORS configuration
- Rate limiting middleware
- Secure file upload handling
- Email verification
- Webhook signature validation

## API Documentation
For detailed API documentation, please refer to the Swagger/OpenAPI documentation available at `/api-docs` when the server is running.

### File Uploads
- CV files are stored in the `uploads` directory
- Maximum file size: 10MB
- Allowed file types: PDF, DOC, DOCX
- Files are automatically renamed to prevent conflicts
- File metadata is stored in database

### Authentication Flow
1. User registration:
   - Email verification required
   - Password must meet complexity requirements
   - CV upload optional during registration

2. Login process:
   - JWT token issued upon successful login
   - Token refresh mechanism
   - Session management

3. Password recovery:
   - Email-based password reset
   - Temporary reset token
   - Security questions option

### Payment Processing
- Stripe integration for payments
- Secure checkout process
- Webhook validation for payment status
- VIP subscription handling
- Freelance project payments
- Refund processing

### Error Handling
- Comprehensive error responses
- Rate limiting protection
- Input validation
- File upload validation
- Authentication errors
- Payment processing errors

### Database Schema
- Users: Stores user information and authentication data
- Jobs: Stores job postings and related information
- FreelanceProjects: Stores freelance project details
- Proposals: Stores job/freelance project proposals
- Payments: Stores payment transactions
- VIPSubscriptions: Stores VIP subscription information

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
ISC License