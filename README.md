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
│   ├── Notification.js
│   └── ...other models
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

### Profile Management
- GET `/api/profile` - Get user profile
- PUT `/api/profile` - Update profile
- POST `/api/profile/upload-cv` - Upload CV

### Company Management
- POST `/api/companies` - Create company
- GET `/api/companies` - Get all companies
- PUT `/api/companies/:id` - Update company
  - Query parameters:
    - `category` - Filter by project category
    - `budget_range` - Filter by budget range
- POST `/api/freelance` - Create new freelance project
  - Required fields:
    - title
    - description
    - budget
    - category
  - Response: Created project object with ID
- GET `/api/freelance/:id` - Get project details
  - Includes creator information
  - Includes proposals count
- PUT `/api/freelance/:id` - Update project
  - Requires authentication
  - Only accessible by project creator
- DELETE `/api/freelance/:id` - Delete project
  - Requires authentication
  - Only accessible by project creator

### Proposals
- POST `/api/proposals` - Submit job proposal
- GET `/api/proposals` - Get proposals for a job
- PUT `/api/proposals/:id` - Update proposal status

### Payments
- POST `/api/payment/create-checkout-session` - Create Stripe checkout session
- POST `/api/payment/webhook` - Stripe webhook endpoint

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