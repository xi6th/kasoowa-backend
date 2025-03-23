# Kasoowa API

A robust, scalable backend API built with Rust, Actix Web, and PostgreSQL, designed for e-commerce marketplaces that connect vendors, affiliates, and customers.

## Features

- **🔐 Authentication System**: JWT-based authentication with refresh tokens and role-based access control
- **👥 User Management**: Support for multiple user types (customers, vendors, affiliates) with different roles and permissions
- **🚀 Event-Driven Architecture**: Kafka integration for event publishing and consumption
- **💾 PostgreSQL Database**: Robust data persistence with Diesel ORM
- **🐳 Docker Deployment**: Full containerization with Docker Compose
- **📊 Monitoring**: Prometheus metrics, Grafana dashboards, and colorized logging
- **🔍 Observability**: Request/response logging and error tracking
- **🌐 Reverse Proxy**: Nginx configuration for routing and security

## Tech Stack

- **Language**: Rust 1.81+
- **Web Framework**: Actix Web
- **Database**: PostgreSQL with Diesel ORM
- **Authentication**: JWT (jsonwebtoken)
- **Password Hashing**: bcrypt
- **Message Broker**: Apache Kafka
- **Caching**: Redis
- **Monitoring**: Prometheus + Grafana
- **Proxy**: Nginx
- **Containerization**: Docker + Docker Compose

## Project Structure

```
kasoowa/
├── src/
│   ├── config.rs        # Application configuration
│   ├── errors.rs        # Custom error handling
│   ├── event_handlers.rs # Kafka event handlers
│   ├── kafka.rs         # Kafka producer and consumer
│   ├── lib.rs           # Library exports
│   ├── logger.rs        # Custom logging setup
│   ├── main.rs          # Application entry point
│   ├── middleware.rs    # Actix middleware components
│   ├── models.rs        # Database models and DTOs
│   ├── schema.rs        # Database schema definitions
│   └── services.rs      # Business logic services
├── Dockerfile           # Container definition
├── docker-compose.yml   # Multi-container setup
├── nginx.conf           # Nginx configuration
├── prometheus.yml       # Prometheus configuration
└── README.md            # Project documentation
```

## Prerequisites

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Rust](https://www.rust-lang.org/tools/install) (for local development)

## Getting Started

### Using Docker Compose (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/kasoowa.git
   cd kasoowa
   ```

2. Create a `.env` file in the project root:
   ```
   DB_USER=postgres
   DB_PASSWORD=postgres
   DB_NAME=kasoowa
   JWT_SECRET=your_secure_random_string
   JWT_EXPIRY_HOURS=24
   REFRESH_EXPIRY_DAYS=30
   RUST_LOG=debug
   ```

3. Run the setup script to create required directories and configurations:
   ```bash
   chmod +x setup-dirs.sh
   ./setup-dirs.sh
   ```

4. Build and start all services:
   ```bash
   docker-compose up --build
   ```

5. The services will be available at:
   - API: http://localhost:8000/api
   - Kafka UI: http://localhost:8000/kafka
   - PgAdmin: http://localhost:8000/pgadmin
   - Grafana: http://localhost:8000/grafana
   - Prometheus: http://localhost:8000/prometheus

### Local Development

1. Install PostgreSQL and Kafka locally
   
2. Create a `.env` file with appropriate connection details:
   ```
   DATABASE_URL=postgres://postgres:postgres@localhost:5432/kasoowa
   KAFKA_BOOTSTRAP_SERVERS=localhost:9092
   JWT_SECRET=your_secure_random_string
   JWT_EXPIRY_HOURS=24
   REFRESH_EXPIRY_DAYS=30
   RUST_LOG=debug
   ```

3. Install dependencies and run:
   ```bash
   cargo build
   cargo run
   ```

## API Endpoints

### Authentication

- `POST http://localhost:8000/api/login` - User login
- `POST http://localhost:8000/api/refresh-token` - Refresh JWT token

### User Management

- `GET http://localhost:8000/api/users` - List users
- `POST http://localhost:8000/api/users` - Create a new user
- `GET http://localhost:8000/api/roles` - Get available roles
- `POST http://localhost:8000/api/users/{user_id}/roles` - Assign role to user

### Vendor Operations

- `POST http://localhost:8000/api/vendor/register` - Register as a vendor

### Affiliate Operations

- `POST http://localhost:8000/api/affiliate/register` - Register as an affiliate

### System

- `GET http://localhost:8000/api/health` - Health check endpoint

## Database Schema

The application uses several key tables:

- `user_account`: Stores user information
- `role_type`: Defines available roles (customer, vendor, affiliate)
- `user_role`: Maps users to roles
- `refresh_token`: Stores refresh tokens for authenticated users
- `admin` and `admin_role_type`: Handles admin users and their roles

## Event System

The application uses Kafka for event-driven architecture with these topics:

- `user-events`: User creation and update events
- `auth-events`: Authentication events
- `vendor-events`: Vendor-specific events
- `affiliate-events`: Affiliate-specific events

## Docker Services

The `docker-compose.yml` configures the following services:

- `api`: Rust Actix Web API service
- `postgres`: PostgreSQL database
- `redis`: Redis for caching (future implementation)
- `kafka` and `zookeeper`: Apache Kafka message broker
- `kafka-ui`: Web UI for Kafka management
- `pgadmin`: PostgreSQL administration
- `prometheus`: Metrics collection
- `grafana`: Metrics visualization
- `nginx`: Reverse proxy and request routing

## Configuration Options

Key environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | postgres://postgres:postgres@postgres:5432/kasoowa |
| `JWT_SECRET` | Secret key for JWT signing | `your_jwt_secret_key_here` |
| `JWT_EXPIRY_HOURS` | JWT token expiration in hours | 24 |
| `REFRESH_EXPIRY_DAYS` | Refresh token expiration in days | 30 |
| `RUST_LOG` | Log level (info, debug, warn, error) | info |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka connection string | kafka:9092 |

## Extending the API

To add new functionality:

1. Define model in `models.rs`
2. Update database schema in `schema.rs` (if needed)
3. Add service methods in `services.rs`
4. Create API endpoints in `main.rs`
5. Add events to `event_handlers.rs` if needed

## Monitoring and Observability

The project includes:

- Colorized logging with different levels
- Request/response timing information
- Prometheus metrics (accessible at `/api/metrics`)
- Grafana dashboards for visualizing metrics
- Error tracking with structured logs

## Security Features

- Password hashing with bcrypt
- JWT authentication with refresh tokens
- Role-based access control
- SQL injection protection via Diesel ORM
- Security headers via Nginx
- Connection rate limiting

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Submit a pull request

## License

[MIT](LICENSE)