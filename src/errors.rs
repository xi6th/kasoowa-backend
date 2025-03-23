use actix_web::{error::ResponseError, HttpResponse};
use std::fmt;
use std::error::Error as StdError;
use serde_json::json;
use log::{warn, error, debug};

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