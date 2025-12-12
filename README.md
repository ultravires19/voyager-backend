# AxeBase Backend

A Rust backend for the AxeBase full-stack application starter, built with Axum and PostgreSQL.

## Overview

This backend serves as a foundational API server for web applications, with a focus on authentication, database patterns, and clean architecture. It provides:

- JWT-based authentication system
- PostgreSQL database integration using sqlx
- REST API endpoints for auth operations
- Modular architecture for future extension

## Getting Started

### Prerequisites

- Rust (latest stable)
- PostgreSQL (or Docker for containerized development)
- pnpm (for frontend development)

### Setup

1. **Start the PostgreSQL database**:

   ```bash
   # From the project root
   docker compose up postgres -d
   ```

2. **Create a .env file** (in the backend directory):

   ```
   DATABASE_URL=postgres://postgres:postgres@localhost:5432/axebase
   JWT_SECRET=your-development-secret-key-change-me
   BIND_ADDR=127.0.0.1:3000
   ```

3. **Build and run the server**:

   ```bash
   # From the backend directory
   cargo run
   ```

## Project Structure

```
backend/
├── src/
│   ├── main.rs            # Server setup and configuration
│   ├── routes/            # API route handlers
│   │   ├── mod.rs         # Routes module
│   │   └── auth.rs        # Auth endpoints
│   ├── db/                # Database interactions
│   │   ├── mod.rs         # DB module
│   │   └── users.rs       # User table queries
│   ├── models/            # Domain models
│   │   ├── mod.rs         # Models module
│   │   └── user.rs        # User model
│   └── utils/             # Utility functions
│       ├── mod.rs         # Utils module
│       ├── error.rs       # Error handling
│       ├── jwt.rs         # JWT handling
│       └── password.rs    # Password hashing
└── migrations/            # SQL migrations
    └── 20240101000000_create_users_table.sql
```

## API Endpoints

### Auth Routes

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login with credentials
- `GET /auth/verify-email/:token` - Verify email address (placeholder)

## Development

### Running Migrations

Migrations are applied automatically on server startup. For manual migration:

```bash
# Install sqlx-cli if needed
cargo install sqlx-cli

# Run migrations
sqlx migrate run
```

### Environment Variables

- `DATABASE_URL` - PostgreSQL connection URL
- `JWT_SECRET` - Secret key for JWT tokens
- `BIND_ADDR` - Server bind address (default: 127.0.0.1:3000)

## License

MIT