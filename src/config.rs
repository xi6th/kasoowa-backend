use diesel::r2d2::{self, ConnectionManager};
use diesel::pg::PgConnection;
use std::env;
use log::warn;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::fmt;
use std::error::Error as StdError;
use actix_web::{error::ResponseError, HttpResponse};
use serde_json::json;
use log::{error, debug};

// Type aliases
pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbError = Box<dyn StdError + Send + Sync>;

// Custom error handling
#[derive(Debug)]
pub enum ApiError {
    DatabaseError(String),
    ValidationError(String),
    AuthError(String),
    NotFoundError(String),
    InternalError(String),
}

impl StdError for ApiError {}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ApiError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            ApiError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            ApiError::AuthError(msg) => write!(f, "Authentication error: {}", msg),
            ApiError::NotFoundError(msg) => write!(f, "Not found: {}", msg),
            ApiError::InternalError(msg) => write!(f, "Internal server error: {}", msg),
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::DatabaseError(msg) => {
                error!("\x1B[1;31mDATABASE ERROR:\x1B[0m {}", msg);
                HttpResponse::InternalServerError().json(json!({ "error": msg }))
            },
            ApiError::ValidationError(msg) => {
                warn!("\x1B[1;33mVALIDATION ERROR:\x1B[0m {}", msg);
                HttpResponse::BadRequest().json(json!({ "error": msg }))
            },
            ApiError::AuthError(msg) => {
                warn!("\x1B[1;33mAUTHENTICATION ERROR:\x1B[0m {}", msg);
                HttpResponse::Unauthorized().json(json!({ "error": msg }))
            },
            ApiError::NotFoundError(msg) => {
                debug!("\x1B[1;36mNOT FOUND ERROR:\x1B[0m {}", msg);
                HttpResponse::NotFound().json(json!({ "error": msg }))
            },
            ApiError::InternalError(msg) => {
                error!("\x1B[1;31mINTERNAL SERVER ERROR:\x1B[0m {}", msg);
                HttpResponse::InternalServerError().json(json!({ "error": msg }))
            },
        }
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            ApiError::DatabaseError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ValidationError(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ApiError::AuthError(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            ApiError::NotFoundError(_) => actix_web::http::StatusCode::NOT_FOUND,
            ApiError::InternalError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// Database initialization SQL - with the fixed DO block syntax
pub const DB_INIT_SQL: &str = r#"
-- Create tables if they don't exist
CREATE TABLE IF NOT EXISTS user_account (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(50),
    date_registered TIMESTAMP NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login TIMESTAMP,
    profile_image VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS role_type (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS user_role (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    assigned_date TIMESTAMP NOT NULL DEFAULT NOW(),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS admin (
    admin_id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role_type_id INTEGER NOT NULL,
    last_login TIMESTAMP,
    permission_level INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS admin_role_type (
    role_type_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS refresh_token (
    token_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_session (
    session_id SERIAL PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    session_token VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50),
    user_agent VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Add foreign keys if not exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_user_role_user'
    ) THEN
        ALTER TABLE user_role ADD CONSTRAINT fk_user_role_user
        FOREIGN KEY (user_id) REFERENCES user_account(user_id) ON DELETE CASCADE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_user_role_role'
    ) THEN
        ALTER TABLE user_role ADD CONSTRAINT fk_user_role_role
        FOREIGN KEY (role_id) REFERENCES role_type(role_id) ON DELETE CASCADE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_admin_role_type'
    ) THEN
        ALTER TABLE admin ADD CONSTRAINT fk_admin_role_type
        FOREIGN KEY (role_type_id) REFERENCES admin_role_type(role_type_id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_refresh_token_user'
    ) THEN
        ALTER TABLE refresh_token ADD CONSTRAINT fk_refresh_token_user
        FOREIGN KEY (user_id) REFERENCES user_account(user_id) ON DELETE CASCADE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_admin_session_admin'
    ) THEN
        ALTER TABLE admin_session ADD CONSTRAINT fk_admin_session_admin
        FOREIGN KEY (admin_id) REFERENCES admin(admin_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Insert initial roles if not exist
INSERT INTO role_type (role_name, description)
VALUES 
    ('customer', 'Regular customer with basic privileges'),
    ('vendor', 'Seller with product management privileges'),
    ('affiliate', 'Affiliate partner with promotional privileges')
ON CONFLICT (role_name) DO NOTHING;

-- Insert initial admin roles if not exist
INSERT INTO admin_role_type (role_name, description)
VALUES 
    ('super_admin', 'Full system access with all privileges'),
    ('support_admin', 'Customer support with limited admin privileges'),
    ('moderator', 'Content moderation privileges')
ON CONFLICT (role_name) DO NOTHING;
"#;

// Config
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub jwt_expiry: i64, // In hours
    pub refresh_expiry: i64, // In days
}

impl AppConfig {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        
        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(val) => val,
            Err(e) => {
                warn!("Failed to load JWT_SECRET: {}", e);
                warn!("Using default JWT secret - THIS IS NOT SECURE FOR PRODUCTION!");
                "your_jwt_secret_key_here".to_string()
            }
        };
        
        let jwt_expiry = env::var("JWT_EXPIRY_HOURS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(24);
        
        let refresh_expiry = env::var("REFRESH_EXPIRY_DAYS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(30);
        
        Self { jwt_secret, jwt_expiry, refresh_expiry }
    }
    
    pub fn validate(&self) -> Result<(), String> {
        if self.jwt_secret == "your_jwt_secret_key_here" {
            warn!("Using default JWT secret is not secure for production!");
        }
        
        if self.jwt_expiry <= 0 {
            return Err("JWT_EXPIRY_HOURS must be positive".to_string());
        }
        
        if self.refresh_expiry <= 0 {
            return Err("REFRESH_EXPIRY_DAYS must be positive".to_string());
        }
        
        Ok(())
    }
    
    pub fn generate_secure_secret() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }
}