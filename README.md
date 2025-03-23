# Rust Actix Web API with Docker

This project is a Rust Actix Web API with PostgreSQL database backend, containerized with Docker.

## Features

- User authentication with JWT
- Role-based access control
- Password reset functionality
- Product management
- Error logging and handling
- Docker deployment

## Prerequisites

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Getting Started

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Create a `.env` file in the project root with the following content:
   ```
   DATABASE_URL=postgres://postgres:postgres@db:5432/app_db
   JWT_SECRET=your_secure_jwt_secret
   JWT_EXPIRY_HOURS=24
   REFRESH_EXPIRY_DAYS=30
   APP_ENV=development
   LOG_LEVEL=info
   LOG_FILE=/app/logs/api_server.log
   ```

3. Build and start the containers:
   ```bash
   docker-compose up --build
   ```

4. The API will be accessible at `http://localhost:8080`

## API Endpoints

### Authentication

- `POST /api/login` - User login
- `POST /api/refresh_token` - Refresh JWT token

### User Management

- `GET /api/users` - List all users
- `POST /api/users` - Create a new user
- `POST /api/register/vendor` - Register as a vendor
- `POST /api/register/affiliate` - Register as an affiliate
- `GET /api/roles` - List available roles
- `POST /api/users/{user_id}/roles` - Assign a role to a user

### Password Reset

- `POST /api/forgot-password` - Request password reset
- `GET /api/verify-reset-token` - Verify reset token
- `POST /api/reset-password` - Reset password

### Product Management

- `POST /api/products` - Create a product
- `PUT /api/products/{product_id}` - Update a product
- `GET /api/vendor/products` - Get vendor products
- `GET /api/products/{product_id}` - Get product details
- `DELETE /api/products/{product_id}` - Delete a product
- `POST /api/products/{product_id}/toggle-status` - Toggle product status
- `GET /api/products/stats` - Get product statistics
- `GET /api/categories` - Get product categories

## Development

### Running Locally Without Docker

If you want to run the application without Docker:

1. Install PostgreSQL locally
2. Update the `.env` file with your local PostgreSQL connection string
3. Run the application:
   ```bash
   cargo run
   ```

### Building for Production

1. Update the `.env` file with production settings
2. Build and run the Docker containers:
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

## License

[MIT](LICENSE)