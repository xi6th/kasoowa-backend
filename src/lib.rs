// This file is needed to make the project structure work correctly
// It exports all the modules for use in the application

pub mod models;
pub mod schema;
pub mod services;
pub mod config;
pub mod middleware;
pub mod logger;
pub mod kafka;
pub mod event_handlers;

// Re-export common types
pub use crate::config::ApiError;
pub use crate::config::AppConfig;
pub use crate::config::DbPool;
pub use crate::models::UserAccount;
pub use crate::kafka::KafkaProducer;