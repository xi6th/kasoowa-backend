use actix_web::{web, error::ResponseError, HttpResponse};
use diesel::prelude::*;
use diesel::connection::SimpleConnection;
use diesel::r2d2::{self, ConnectionManager};
use diesel::pg::PgConnection;
use serde::{Deserialize, Serialize};
use chrono::{Duration, Utc, NaiveDateTime};
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, Header, EncodingKey};
use std::{env, fmt};
use std::error::Error as StdError;
use serde_json::json;
use log::{info, warn, error, debug};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

// Type aliases
pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbError = Box<dyn StdError + Send + Sync>;

// Database initialization SQL
// Database initialization SQL
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
                error!("Database error: {}", msg);
                HttpResponse::InternalServerError().json(json!({ "error": msg }))
            },
            ApiError::ValidationError(msg) => {
                debug!("Validation error: {}", msg);
                HttpResponse::BadRequest().json(json!({ "error": msg }))
            },
            ApiError::AuthError(msg) => {
                debug!("Authentication error: {}", msg);
                HttpResponse::Unauthorized().json(json!({ "error": msg }))
            },
            ApiError::NotFoundError(msg) => {
                debug!("Not found error: {}", msg);
                HttpResponse::NotFound().json(json!({ "error": msg }))
            },
            ApiError::InternalError(msg) => {
                error!("Internal server error: {}", msg);
                HttpResponse::InternalServerError().json(json!({ "error": msg }))
            },
        }
    }
}

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

// Database schema
pub mod schema {
    diesel::table! {
        user_account (user_id) {
            user_id -> Int4,
            email -> Varchar,
            password_hash -> Varchar,
            first_name -> Nullable<Varchar>,
            last_name -> Nullable<Varchar>,
            phone_number -> Nullable<Varchar>,
            date_registered -> Timestamp,
            is_active -> Bool,
            last_login -> Nullable<Timestamp>,
            profile_image -> Nullable<Varchar>,
        }
    }

    diesel::table! {
        role_type (role_id) {
            role_id -> Int4,
            role_name -> Varchar,
            description -> Nullable<Varchar>,
        }
    }

    diesel::table! {
        user_role (user_id, role_id) {
            user_id -> Int4,
            role_id -> Int4,
            assigned_date -> Timestamp,
            is_primary -> Bool,
        }
    }

    diesel::table! {
        admin (admin_id) {
            admin_id -> Int4,
            email -> Varchar,
            password_hash -> Varchar,
            first_name -> Nullable<Varchar>,
            last_name -> Nullable<Varchar>,
            role_type_id -> Int4,
            last_login -> Nullable<Timestamp>,
            permission_level -> Int4,
        }
    }

    diesel::table! {
        admin_role_type (role_type_id) {
            role_type_id -> Int4,
            role_name -> Varchar,
            description -> Nullable<Varchar>,
        }
    }

    diesel::table! {
        refresh_token (token_id) {
            token_id -> Int4,
            user_id -> Int4,
            token -> Varchar,
            expires_at -> Timestamp,
            created_at -> Timestamp,
        }
    }

    diesel::table! {
        admin_session (session_id) {
            session_id -> Int4,
            admin_id -> Int4,
            session_token -> Varchar,
            ip_address -> Nullable<Varchar>,
            user_agent -> Nullable<Varchar>,
            expires_at -> Timestamp,
            created_at -> Timestamp,
        }
    }

    diesel::joinable!(user_role -> user_account (user_id));
    diesel::joinable!(user_role -> role_type (role_id));
    diesel::joinable!(admin -> admin_role_type (role_type_id));
    diesel::joinable!(refresh_token -> user_account (user_id));
    diesel::joinable!(admin_session -> admin (admin_id));

    diesel::allow_tables_to_appear_in_same_query!(
        user_account, role_type, user_role, admin,
        admin_role_type, refresh_token, admin_session,
    );
}

// Models
pub mod models {
    use super::schema::*;
    use chrono::NaiveDateTime;
    use serde::{Deserialize, Serialize};
    use diesel::prelude::*;
    use diesel::sql_types;

    #[derive(Queryable, Serialize, Debug)]
    pub struct UserAccount {
        pub user_id: i32,
        pub email: String,
        #[serde(skip_serializing)]
        pub password_hash: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
        pub phone_number: Option<String>,
        pub date_registered: NaiveDateTime,
        pub is_active: bool,
        pub last_login: Option<NaiveDateTime>,
        pub profile_image: Option<String>,
    }

    #[derive(Insertable, Debug, Clone)]
    #[diesel(table_name = user_account)]
    pub struct NewUserAccount {
        pub email: String,
        pub password_hash: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
        pub phone_number: Option<String>,
        pub profile_image: Option<String>,
    }

    #[derive(Queryable, Serialize, Debug)]
    pub struct RoleType {
        pub role_id: i32,
        pub role_name: String,
        pub description: Option<String>,
    }

    #[derive(Queryable, Serialize, Debug)]
    pub struct UserRole {
        pub user_id: i32,
        pub role_id: i32,
        pub assigned_date: NaiveDateTime,
        pub is_primary: bool,
    }

    #[derive(Insertable, Deserialize, Debug)]
    #[diesel(table_name = user_role)]
    pub struct NewUserRole {
        pub user_id: i32,
        pub role_id: i32,
        pub is_primary: bool,
    }

    #[derive(Queryable, Serialize, Debug)]
    pub struct RefreshToken {
        pub token_id: i32,
        pub user_id: i32,
        pub token: String,
        pub expires_at: NaiveDateTime,
        pub created_at: NaiveDateTime,
    }

    #[derive(Insertable, Debug)]
    #[diesel(table_name = refresh_token)]
    pub struct NewRefreshToken {
        pub user_id: i32,
        pub token: String,
        pub expires_at: NaiveDateTime,
    }

    // DTOs
    #[derive(Deserialize, Debug)]
    pub struct CreateUserRequest {
        pub email: String,
        pub password: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
        pub phone_number: Option<String>,
        pub profile_image: Option<String>,
    }

    #[derive(Deserialize, Debug)]
    pub struct LoginRequest {
        pub email: String,
        pub password: String,
    }

    #[derive(Serialize, Debug)]
    pub struct LoginResponse {
        pub token: String,
        pub refresh_token: String,
        pub user_id: i32,
        pub email: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct Claims {
        pub sub: String,      // Subject (user_id)
        pub exp: usize,       // Expiration time
        pub iat: usize,       // Issued at
        pub user_id: i32,
        pub email: String,
    }

    #[derive(Deserialize, Debug)]
    pub struct VendorRegistrationRequest {
        // Personal Information
        pub first_name: String,
        pub last_name: String,
        pub email: String,
        pub password: String,
        
        // Business Information
        pub business_name: String,
        pub store_url: Option<String>,
        pub country: String,
        pub business_location: String,
        pub business_address: String,
        
        // Business Documents
        pub tax_number: Option<String>,
        pub id_number: Option<String>,
        
        // Bank Information
        pub bank_name: String,
        pub account_number: String,
        pub account_name: String,
        
        // Additional Information
        pub additional_information: Option<String>,
        pub business_type: String,
        
        // Terms
        pub agree_to_terms: bool,
        pub agree_to_privacy: bool
    }

    #[derive(Deserialize, Debug)]
    pub struct AffiliateRegistrationRequest {
        pub full_name: String,
        pub email: String,
        pub phone_number: String,
        pub niche_name: String,
        pub password: String,
        pub confirm_password: String,
        pub description: String,
        
        // Payment Information
        pub bank_name: String,
        pub account_number: String,
        pub account_name: String,
        
        // Terms
        pub agree_to_terms: bool
    }

    #[derive(QueryableByName, Debug)]
    pub struct CountResult {
        #[diesel(sql_type = sql_types::BigInt)]
        pub count: i64,
    }
}

// Services
pub mod services {
    use super::models::*;
    use super::{ApiError, AppConfig, DbPool};
    use actix_web::web;
    use bcrypt::{hash, verify, DEFAULT_COST};
    use chrono::{Duration, Utc};
    use diesel::prelude::*;
    use jsonwebtoken::{encode, Header, EncodingKey};
    use log::{debug, error, info};
    use uuid::Uuid;

    pub struct AuthService;

    impl AuthService {
        pub fn hash_password(password: &str) -> Result<String, ApiError> {
            hash(password, DEFAULT_COST)
                .map_err(|e| {
                    error!("Failed to hash password: {}", e);
                    ApiError::InternalError("Failed to hash password".to_string())
                })
        }
        
        pub fn verify_password(password: &str, hash: &str) -> Result<bool, ApiError> {
            verify(password, hash)
                .map_err(|e| {
                    error!("Failed to verify password: {}", e);
                    ApiError::InternalError("Failed to verify password".to_string())
                })
        }
        
        pub fn generate_token(user_id: i32, email: &str, config: &AppConfig) -> Result<String, ApiError> {
            let now = Utc::now();
            let iat = now.timestamp() as usize;
            let exp = (now + Duration::hours(config.jwt_expiry)).timestamp() as usize;
            
            let claims = Claims {
                sub: user_id.to_string(),
                exp,
                iat,
                user_id,
                email: email.to_string(),
            };
            
            encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(config.jwt_secret.as_bytes())
            )
            .map_err(|e| {
                error!("Failed to generate token: {}", e);
                ApiError::InternalError("Failed to generate token".to_string())
            })
        }
        
        pub fn generate_refresh_token() -> String {
            Uuid::new_v4().to_string()
        }
        
        pub async fn store_refresh_token(
            user_id: i32, 
            token: &str, 
            config: &AppConfig,
            pool: &DbPool
        ) -> Result<(), ApiError> {
            let expires_at = (Utc::now() + Duration::days(config.refresh_expiry)).naive_utc();
            
            let new_token = NewRefreshToken {
                user_id,
                token: token.to_string(),
                expires_at,
            };
            
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            web::block(move || {
                use super::schema::refresh_token::dsl::*;
                let mut conn = conn;
                diesel::insert_into(refresh_token)
                    .values(&new_token)
                    .execute(&mut conn)
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to store refresh token: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?;
            
            Ok(())
        }
        
        pub async fn update_last_login(user_id_param: i32, pool: &DbPool) -> Result<(), ApiError> {
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            web::block(move || {
                use super::schema::user_account::dsl::*;
                let mut conn = conn;
                diesel::update(user_account.find(user_id_param))
                    .set(last_login.eq(Some(Utc::now().naive_utc())))
                    .execute(&mut conn)
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to update last login: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?;
            
            Ok(())
        }
    }

    pub struct UserService;

    impl UserService {
        pub async fn find_by_email(email_addr: &str, pool: &DbPool) -> Result<Option<UserAccount>, ApiError> {
            let email_copy = email_addr.to_string();
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            let user = web::block(move || {
                use super::schema::user_account::dsl::*;
                let mut conn = conn;
                user_account
                    .filter(email.eq(email_copy))
                    .first::<UserAccount>(&mut conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                error!("Error finding user by email: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?;
            
            Ok(user)
        }
        
        pub async fn create_user(user_data: &CreateUserRequest, pool: &DbPool) -> Result<i32, ApiError> {
            let password_hash = AuthService::hash_password(&user_data.password)?;
            
            let new_user = NewUserAccount {
                email: user_data.email.clone(),
                password_hash,
                first_name: user_data.first_name.clone(),
                last_name: user_data.last_name.clone(),
                phone_number: user_data.phone_number.clone(),
                profile_image: user_data.profile_image.clone(),
            };
            
            let new_user_clone = new_user.clone();
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            let user_id = web::block(move || {
                use super::schema::user_account::dsl::*;
                let mut conn = conn;
                diesel::insert_into(user_account)
                    .values(&new_user)
                    .returning(user_id)
                    .get_result::<i32>(&mut conn)
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                if e.to_string().contains("unique constraint") {
                    debug!("Attempted to create user with existing email: {}", new_user_clone.email);
                    ApiError::ValidationError("Email already exists".to_string())
                } else {
                    error!("Failed to create user: {}", e);
                    ApiError::DatabaseError(e.to_string())
                }
            })?;
            
            info!("Created new user with ID: {}", user_id);
            Ok(user_id)
        }
        
        pub async fn get_user_by_id(id: i32, pool: &DbPool) -> Result<UserAccount, ApiError> {
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            let user = web::block(move || {
                use super::schema::user_account::dsl::*;
                let mut conn = conn;
                user_account.find(id).first::<UserAccount>(&mut conn)
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                debug!("User not found with ID {}: {}", id, e);
                ApiError::NotFoundError("User not found".to_string())
            })?;
            
            Ok(user)
        }
        
        pub async fn assign_role(
            user_id: i32, 
            role_id: i32, 
            is_primary: bool, 
            pool: &DbPool
        ) -> Result<(), ApiError> {
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            // Verify user exists
            let user_exists = web::block(move || {
                use super::schema::user_account::dsl::*;
                let mut conn = conn;
                user_account
                    .find(user_id)
                    .select(user_id)
                    .first::<i32>(&mut conn)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                error!("Error checking if user exists: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?;
            
            if user_exists.is_none() {
                debug!("Attempted to assign role to non-existent user ID: {}", user_id);
                return Err(ApiError::NotFoundError("User not found".to_string()));
            }
            
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            let new_role = NewUserRole {
                user_id,
                role_id,
                is_primary,
            };
            
            web::block(move || {
                use super::schema::user_role::dsl::*;
                let mut conn = conn;
                diesel::insert_into(user_role)
                    .values(&new_role)
                    .on_conflict((user_id, role_id))
                    .do_update()
                    .set(is_primary.eq(new_role.is_primary))
                    .execute(&mut conn)
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                error!("Failed to assign role: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?;
            
            info!("Role {} assigned to user {} successfully", role_id, user_id);
            Ok(())
        }
        
        pub async fn find_role_by_name(role_name_param: &str, pool: &DbPool) -> Result<RoleType, ApiError> {
            let role_name_copy = role_name_param.to_string();
            let conn = pool.get()
                .map_err(|e| {
                    error!("Failed to get database connection: {}", e);
                    ApiError::DatabaseError(e.to_string())
                })?;
            
            let role = web::block(move || {
                use super::schema::role_type::dsl::*;
                let mut conn = conn;
                role_type
                    .filter(role_name.eq(role_name_copy))
                    .first::<RoleType>(&mut conn)
            })
            .await
            .map_err(|e| {
                error!("Database operation error: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?
            .map_err(|e| {
                debug!("Role not found with name {}: {}", role_name_param, e);
                ApiError::NotFoundError("Role not found".to_string())
            })?;
            
            Ok(role)
        }
    }
}