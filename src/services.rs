use crate::models::*;
use crate::config::{ApiError, AppConfig, DbPool};
use actix_web::web;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods};
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
            use crate::schema::refresh_token::dsl::*;
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
            use crate::schema::user_account::dsl::*;
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
            use crate::schema::user_account::dsl::*;
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
            use crate::schema::user_account::dsl::*;
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
            use crate::schema::user_account::dsl::*;
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
    
    pub async fn get_user_roles(user_id_param: i32, pool: &DbPool) -> Result<Vec<RoleType>, ApiError> {
        let conn = pool.get()
            .map_err(|e| {
                error!("Failed to get database connection: {}", e);
                ApiError::DatabaseError(e.to_string())
            })?;
        
        let roles = web::block(move || {
            // Import the role_type columns directly to disambiguate
            use crate::schema::role_type::dsl::{role_type, role_id as rt_role_id, role_name, description};
            // Import the user_role columns
            use crate::schema::user_role::dsl::{user_role, user_id, role_id as ur_role_id};
            
            let mut conn = conn;
            
            role_type
                .inner_join(user_role.on(rt_role_id.eq(ur_role_id)))
                .filter(user_id.eq(user_id_param))
                .select((
                    rt_role_id,
                    role_name,
                    description
                ))
                .load::<RoleType>(&mut conn)
        })
        .await
        .map_err(|e| {
            error!("Database operation error: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?
        .map_err(|e| {
            error!("Failed to get user roles: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?;
        
        Ok(roles)
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
            use crate::schema::user_account::dsl::*;
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
            use crate::schema::user_role::dsl::*;
            let mut conn = conn;
            diesel::insert_into(user_role)
                .values(&new_role)
                .on_conflict((user_id, role_id))
                .do_update()
                .set(is_primary.eq(&new_role.is_primary))
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
            use crate::schema::role_type::dsl::*;
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