use std::time::Duration;
use log::{info, error, warn, debug};
use serde::{Serialize, Deserialize};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::consumer::{StreamConsumer, Consumer, CommitMode};
use rdkafka::Message; // Import the Message trait
use rdkafka::error::KafkaError;
use rdkafka::util::Timeout;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// Kafka configuration
#[derive(Clone, Debug)]
pub struct KafkaConfig {
    pub bootstrap_servers: String,
    pub client_id: String,
    pub group_id: String,
}

impl KafkaConfig {
    pub fn from_env() -> Self {
        dotenv::dotenv().ok();
        
        let bootstrap_servers = std::env::var("KAFKA_BOOTSTRAP_SERVERS")
            .unwrap_or_else(|_| "localhost:9092".to_string());
        
        let client_id = std::env::var("KAFKA_CLIENT_ID")
            .unwrap_or_else(|_| "kasoowa-service".to_string());
        
        let group_id = std::env::var("KAFKA_GROUP_ID")
            .unwrap_or_else(|_| "kasoowa-consumers".to_string());
        
        Self {
            bootstrap_servers,
            client_id,
            group_id,
        }
    }
}

// Define an enum that can represent all our Kafka producer types
#[derive(Clone)]
pub enum KafkaProducer {
    Real(RdKafkaProducer),
    Dummy(DummyKafkaProducer),
}

impl KafkaProducer {
    pub async fn send<T: Serialize>(&self, topic: &str, key: Option<&str>, payload: &T) -> Result<(), String> {
        match self {
            KafkaProducer::Real(producer) => producer.send(topic, key, payload).await,
            KafkaProducer::Dummy(producer) => producer.send(topic, key, payload).await,
        }
    }
}

// Concrete implementation
#[derive(Clone)]
pub struct RdKafkaProducer {
    producer: FutureProducer,
}

impl RdKafkaProducer {
    pub fn new(config: &KafkaConfig) -> Result<Self, KafkaError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("client.id", &config.client_id)
            .set("message.timeout.ms", "5000")
            .set("compression.type", "snappy")
            .set("acks", "all")
            .create()?;
        
        Ok(Self { producer })
    }
    
    pub async fn send<T: Serialize>(&self, topic: &str, key: Option<&str>, payload: &T) -> Result<(), String> {
        let json_payload = serde_json::to_string(payload).map_err(|e| format!("Serialization error: {}", e))?;
        
        let record = match key {
            Some(k) => FutureRecord::to(topic).key(k).payload(&json_payload),
            None => FutureRecord::to(topic).payload(&json_payload),
        };
        
        debug!("Sending message to topic {}: {}", topic, json_payload);
        
        match self.producer.send(record, Timeout::After(Duration::from_secs(5))).await {
            Ok((partition, offset)) => {
                info!("Message sent to topic {}, partition {}, offset {}", topic, partition, offset);
                Ok(())
            },
            Err((err, _)) => {
                error!("Failed to send message to Kafka: {}", err);
                Err(format!("Failed to send message: {}", err))
            }
        }
    }
}

// Create a Kafka producer
pub async fn create_producer() -> Result<KafkaProducer, String> {
    let config = KafkaConfig::from_env();
    match RdKafkaProducer::new(&config) {
        Ok(producer) => Ok(KafkaProducer::Real(producer)),
        Err(e) => {
            error!("Failed to create RdKafkaProducer: {}", e);
            Ok(KafkaProducer::Dummy(DummyKafkaProducer::new()))
        }
    }
}

// Dummy producer for fallback when Kafka is unavailable
#[derive(Clone)]
pub struct DummyKafkaProducer {}

impl DummyKafkaProducer {
    pub fn new() -> Self {
        Self {}
    }
    
    pub async fn send<T: Serialize>(&self, topic: &str, key: Option<&str>, payload: &T) -> Result<(), String> {
        warn!("Using dummy Kafka producer. Message to topic '{}' not sent.", topic);
        // Just log the message but don't fail the operation
        if let Ok(json) = serde_json::to_string(payload) {
            debug!("Would have sent: key={:?}, payload={}", key, json);
        }
        Ok(())
    }
}

// Kafka consumer wrapper
pub struct KafkaConsumer {
    consumer: StreamConsumer,
    running: Arc<Mutex<bool>>,
    handlers: Vec<JoinHandle<()>>,
}

impl KafkaConsumer {
    pub fn new(config: &KafkaConfig) -> Result<Self, KafkaError> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("group.id", &config.group_id)
            .set("client.id", &config.client_id)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("session.timeout.ms", "6000")
            .create()?;
        
        Ok(Self { 
            consumer,
            running: Arc::new(Mutex::new(true)),
            handlers: Vec::new(), 
        })
    }
    
    pub async fn subscribe<F, Fut>(&mut self, topics: &[&str], message_handler: F) -> Result<(), KafkaError> 
    where
        F: Fn(String, String) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.consumer.subscribe(topics)?;
        info!("Subscribed to topics: {:?}", topics);
        
        let running = self.running.clone();
        let handler = message_handler.clone();
        
        // Clone the topics to own them inside the worker
        let topics_owned: Vec<String> = topics.iter().map(|&t| t.to_string()).collect();
        
        // Start a worker task that will process messages
        let worker = tokio::spawn(async move {
            // We need to create a new consumer for the worker
            let worker_config = KafkaConfig::from_env();
            let worker_consumer = match ClientConfig::new()
                .set("bootstrap.servers", &worker_config.bootstrap_servers)
                .set("group.id", &worker_config.group_id)
                .set("client.id", &format!("{}-worker", &worker_config.client_id))
                .set("enable.auto.commit", "false")
                .set("auto.offset.reset", "earliest")
                .set("session.timeout.ms", "6000")
                .create::<StreamConsumer>() {
                    Ok(consumer) => consumer,
                    Err(e) => {
                        error!("Failed to create worker consumer: {}", e);
                        return;
                    }
                };
            
            // Convert owned topics back to &str for subscribe method
            let topics_str: Vec<&str> = topics_owned.iter().map(|s| s.as_str()).collect();
            
            // Subscribe to the same topics
            if let Err(e) = worker_consumer.subscribe(&topics_str) {
                error!("Failed to subscribe worker consumer: {}", e);
                return;
            }
            
            // Process messages
            while *running.lock().await {
                match worker_consumer.recv().await {
                    Ok(message) => {
                        let payload = match message.payload() {
                            Some(bytes) => match std::str::from_utf8(bytes) {
                                Ok(s) => s.to_owned(),
                                Err(e) => {
                                    error!("Error converting message payload to UTF-8: {}", e);
                                    worker_consumer.commit_message(&message, CommitMode::Async).unwrap();
                                    continue;
                                }
                            },
                            None => {
                                warn!("Empty message payload");
                                worker_consumer.commit_message(&message, CommitMode::Async).unwrap();
                                continue;
                            }
                        };
                        
                        let key = match message.key() {
                            Some(bytes) => match std::str::from_utf8(bytes) {
                                Ok(s) => s.to_owned(),
                                Err(_) => String::new(),
                            },
                            None => String::new(),
                        };
                        
                        debug!("Received message: key={}, payload={}", key, payload);
                        
                        // Process message using the provided handler
                        handler(key, payload).await;
                        
                        // Commit the message offset
                        if let Err(e) = worker_consumer.commit_message(&message, CommitMode::Async) {
                            error!("Failed to commit message: {}", e);
                        }
                    },
                    Err(e) => {
                        error!("Error while receiving message: {:?}", e);
                    },
                }
            }
        });
        
        self.handlers.push(worker);
        Ok(())
    }
    
    pub async fn stop(&mut self) {
        let mut running = self.running.lock().await;
        *running = false;
        
        for handler in self.handlers.drain(..) {
            // Don't panic if a handler has already been shutdown
            let _ = handler.await;
        }
    }
}

// Event types for Kafka messages
#[derive(Debug, Serialize, Deserialize)]
pub enum EventType {
    UserCreated,
    UserUpdated,
    UserLogin,
    VendorRegistered,
    AffiliateRegistered,
}

// Generic event structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Event<T> {
    pub event_type: EventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub payload: T,
}

impl<T> Event<T> {
    pub fn new(event_type: EventType, payload: T) -> Self {
        Self {
            event_type,
            timestamp: chrono::Utc::now(),
            payload,
        }
    }
}

// Event-specific topics
pub const TOPIC_USER_EVENTS: &str = "user-events";
pub const TOPIC_AUTH_EVENTS: &str = "auth-events";
pub const TOPIC_VENDOR_EVENTS: &str = "vendor-events";
pub const TOPIC_AFFILIATE_EVENTS: &str = "affiliate-events";