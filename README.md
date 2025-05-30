# Employment Website Backend Documentation

## Project Overview
This is the backend server for an employment website that connects employers with job seekers and freelancers. The system provides comprehensive features including:
- Job posting and management
- Freelance project management
- User authentication and authorization
- Payment processing
- CV upload and management
- Email notifications
- VIP subscription plans
- Secure webhook integration

## Tech Stack
- Node.js/Express.js
- MongoDB (using Mongoose)
- JWT for authentication
- Stripe for payment processing
- SendGrid for email services

## Project Structure
```
employment_backend/
├── config/           # Configuration files
├── controllers/      # Business logic
├── middleware/       # Request/response interceptors
├── models/          # Database models
├── routes/          # API routes
├── utils/           # Utility functions
├── uploads/         # File upload storage
├── server.js        # Main application file
└── .env            # Environment variables
```

## API Endpoints

### Authentication
- POST `/api/auth/register` - Register new user
- POST `/api/auth/login` - User login
- POST `/api/auth/forgot-password` - Password reset request
- POST `/api/auth/reset-password` - Reset password
- POST `/api/auth/upload-cv` - Upload CV file (stored in uploads folder)

### Jobs
- GET `/api/jobs` - List all jobs
  - Query parameters: 
    - `category` - Filter by job category
    - `location` - Filter by location
    - `salary_range` - Filter by salary range
- POST `/api/jobs` - Create new job posting
  - Required fields:
    - title
    - description
    - company
    - location
    - salary
  - Response: Created job object with ID
- GET `/api/jobs/:id` - Get job details
  - Includes creator information
- PUT `/api/jobs/:id` - Update job posting
  - Requires authentication
  - Only accessible by job creator
- DELETE `/api/jobs/:id` - Delete job posting
  - Requires authentication
  - Only accessible by job creator

### Freelance Projects
- GET `/api/freelance` - List all freelance projects
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