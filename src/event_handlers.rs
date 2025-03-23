use crate::kafka::{Event, EventType, KafkaProducer};
use crate::models::{UserAccount, LoginResponse, VendorRegistrationRequest, AffiliateRegistrationRequest};
use log::{info, error};
use serde::{Serialize, Deserialize};
use std::sync::Arc;

// Event payloads
#[derive(Debug, Serialize, Deserialize)]
pub struct UserCreatedEvent {
    pub user_id: i32,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginEvent {
    pub user_id: i32,
    pub email: String,
    pub ip_address: Option<String>,
    pub login_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VendorRegisteredEvent {
    pub user_id: i32,
    pub email: String,
    pub business_name: String,
    pub business_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AffiliateRegisteredEvent {
    pub user_id: i32,
    pub email: String,
    pub niche: String,
}

// Event publisher service
pub struct EventPublisher {
    producer: Arc<KafkaProducer>,
}

impl EventPublisher {
    pub fn new(producer: Arc<KafkaProducer>) -> Self {
        Self { producer }
    }
    
    pub async fn publish_user_created(&self, user: &UserAccount, roles: Vec<String>) -> Result<(), String> {
        let event = Event::new(
            EventType::UserCreated,
            UserCreatedEvent {
                user_id: user.user_id,
                email: user.email.clone(),
                roles,
            }
        );
        
        self.producer.send(crate::kafka::TOPIC_USER_EVENTS, Some(&user.user_id.to_string()), &event).await
    }
    
    pub async fn publish_user_login(&self, login_response: &LoginResponse, ip_address: Option<String>) -> Result<(), String> {
        let event = Event::new(
            EventType::UserLogin,
            UserLoginEvent {
                user_id: login_response.user_id,
                email: login_response.email.clone(),
                ip_address,
                login_timestamp: chrono::Utc::now(),
            }
        );
        
        self.producer.send(crate::kafka::TOPIC_AUTH_EVENTS, Some(&login_response.user_id.to_string()), &event).await
    }
    
    pub async fn publish_vendor_registered(&self, user_id: i32, data: &VendorRegistrationRequest) -> Result<(), String> {
        let event = Event::new(
            EventType::VendorRegistered,
            VendorRegisteredEvent {
                user_id,
                email: data.email.clone(),
                business_name: data.business_name.clone(),
                business_type: data.business_type.clone(),
            }
        );
        
        self.producer.send(crate::kafka::TOPIC_VENDOR_EVENTS, Some(&user_id.to_string()), &event).await
    }
    
    pub async fn publish_affiliate_registered(&self, user_id: i32, data: &AffiliateRegistrationRequest) -> Result<(), String> {
        let event = Event::new(
            EventType::AffiliateRegistered,
            AffiliateRegisteredEvent {
                user_id,
                email: data.email.clone(),
                niche: data.niche_name.clone(),
            }
        );
        
        self.producer.send(crate::kafka::TOPIC_AFFILIATE_EVENTS, Some(&user_id.to_string()), &event).await
    }
}

// Event consumer handlers
pub async fn handle_user_event(_key: String, payload: String) {
    match serde_json::from_str::<Event<UserCreatedEvent>>(&payload) {
        Ok(event) => {
            match event.event_type {
                EventType::UserCreated => {
                    info!(
                        "User created event processed - User ID: {}, Email: {}, Roles: {:?}",
                        event.payload.user_id, event.payload.email, event.payload.roles
                    );
                    // Add custom processing logic here
                },
                _ => {
                    info!("Received other user event type: {:?}", event.event_type);
                }
            }
        },
        Err(e) => {
            error!("Failed to deserialize user event: {}", e);
        }
    }
}

pub async fn handle_auth_event(_key: String, payload: String) {
    match serde_json::from_str::<Event<UserLoginEvent>>(&payload) {
        Ok(event) => {
            match event.event_type {
                EventType::UserLogin => {
                    info!(
                        "User login event processed - User ID: {}, Email: {}, Time: {}",
                        event.payload.user_id, event.payload.email, event.payload.login_timestamp
                    );
                    // Add custom processing logic here (e.g., recording login attempts)
                },
                _ => {
                    info!("Received other auth event type: {:?}", event.event_type);
                }
            }
        },
        Err(e) => {
            error!("Failed to deserialize auth event: {}", e);
        }
    }
}

pub async fn handle_vendor_event(_key: String, payload: String) {
    match serde_json::from_str::<Event<VendorRegisteredEvent>>(&payload) {
        Ok(event) => {
            match event.event_type {
                EventType::VendorRegistered => {
                    info!(
                        "Vendor registered event processed - User ID: {}, Business: {}",
                        event.payload.user_id, event.payload.business_name
                    );
                    // Add custom processing logic here
                },
                _ => {
                    info!("Received other vendor event type: {:?}", event.event_type);
                }
            }
        },
        Err(e) => {
            error!("Failed to deserialize vendor event: {}", e);
        }
    }
}

pub async fn handle_affiliate_event(_key: String, payload: String) {
    match serde_json::from_str::<Event<AffiliateRegisteredEvent>>(&payload) {
        Ok(event) => {
            match event.event_type {
                EventType::AffiliateRegistered => {
                    info!(
                        "Affiliate registered event processed - User ID: {}, Niche: {}",
                        event.payload.user_id, event.payload.niche
                    );
                    // Add custom processing logic here
                },
                _ => {
                    info!("Received other affiliate event type: {:?}", event.event_type);
                }
            }
        },
        Err(e) => {
            error!("Failed to deserialize affiliate event: {}", e);
        }
    }
}