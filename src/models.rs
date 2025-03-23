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
#[diesel(table_name = crate::schema::user_account)]
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
#[diesel(table_name = crate::schema::user_role)]
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
#[diesel(table_name = crate::schema::refresh_token)]
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