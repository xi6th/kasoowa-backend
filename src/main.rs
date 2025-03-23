use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::{Connection, QueryDsl, RunQueryDsl, ExpressionMethods};
use serde_json::json;
use log::{info, debug, error, warn};
use std::env;
use std::sync::Arc;
use tokio::sync::OnceCell;

// Import types from the crate (lib.rs)
use kasoowa::models::{
    UserAccount, CreateUserRequest, RoleType, NewUserRole, 
    LoginRequest, LoginResponse, RefreshToken, 
    VendorRegistrationRequest, AffiliateRegistrationRequest
};
use kasoowa::services::{AuthService, UserService};
use kasoowa::config::{ApiError, AppConfig, DbPool, DB_INIT_SQL};
use kasoowa::middleware::RequestLogger;
use kasoowa::logger::setup_logger;
use kasoowa::kafka::{KafkaProducer, KafkaConsumer, KafkaConfig, DummyKafkaProducer};
use kasoowa::event_handlers::{EventPublisher, handle_user_event, handle_auth_event, handle_vendor_event, handle_affiliate_event};

// Global Kafka producer singleton
static KAFKA_PRODUCER: OnceCell<Arc<KafkaProducer>> = OnceCell::const_new();

async fn get_kafka_producer() -> Arc<KafkaProducer> {
    KAFKA_PRODUCER.get_or_init(|| async {
        match kasoowa::kafka::create_producer().await {
            Ok(producer) => Arc::new(producer),
            Err(e) => {
                error!("Failed to create Kafka producer: {}. Using dummy producer.", e);
                Arc::new(KafkaProducer::Dummy(DummyKafkaProducer::new()))
            }
        }
    }).await.clone()
}


#[get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}


#[get("/users")]
async fn list_users(pool: web::Data<DbPool>) -> Result<HttpResponse, ApiError> {
    let conn = pool.get()
        .map_err(|e| {
            error!("Failed to get database connection: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?;
    
    let users = web::block(move || {
        use kasoowa::schema::user_account::dsl::*;
        let mut conn = conn;
        user_account.limit(10).load::<UserAccount>(&mut conn)
    })
    .await
    .map_err(|e| {
        error!("Database operation error: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?
    .map_err(|e| {
        error!("Failed to list users: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?;
    
    debug!("Listed {} users", users.len());
    Ok(HttpResponse::Ok().json(users))
}

#[post("/users")]
async fn create_user(
    pool: web::Data<DbPool>,
    user_data: web::Json<CreateUserRequest>,
    _req: HttpRequest
    
) -> Result<HttpResponse, ApiError> {
    debug!("Create user request received for email: {}", user_data.email);
    let user_id = UserService::create_user(&user_data, &pool).await?;
    let user = UserService::get_user_by_id(user_id, &pool).await?;
    
    // Get user roles
    let roles = UserService::get_user_roles(user_id, &pool).await?;
    let role_names = roles.iter().map(|r| r.role_name.clone()).collect();
    
    // Publish user created event - with explicit type annotations
    let producer = get_kafka_producer().await;
    let event_publisher = EventPublisher::new(producer);
    
    if let Err(e) = event_publisher.publish_user_created(&user, role_names).await {
        warn!("Failed to publish user created event: {}", e);
    }
    
    // Explicit type annotation for the response
    let response: HttpResponse = HttpResponse::Created().json(user);
    Ok(response)
}

#[get("/roles")]
async fn list_roles(pool: web::Data<DbPool>) -> Result<HttpResponse, ApiError> {
    let conn = pool.get()
        .map_err(|e| {
            error!("Failed to get database connection: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?;
    
    let roles = web::block(move || {
        use kasoowa::schema::role_type::dsl::*;
        let mut conn = conn;
        role_type.load::<RoleType>(&mut conn)
    })
    .await
    .map_err(|e| {
        error!("Database operation error: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?
    .map_err(|e| {
        error!("Failed to list roles: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?;
    
    debug!("Listed {} roles", roles.len());
    Ok(HttpResponse::Ok().json(roles))
}

#[post("/users/{user_id}/roles")]
async fn assign_role(
    pool: web::Data<DbPool>,
    path: web::Path<i32>,
    role_data: web::Json<NewUserRole>
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    debug!("Assigning role {} to user {}", role_data.role_id, user_id);
    
    UserService::assign_role(
        user_id,
        role_data.role_id,
        role_data.is_primary,
        &pool
    ).await?;
    
    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "message": "Role assigned successfully"
    })))
}

#[post("/login")]
async fn login(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    login_data: web::Json<LoginRequest>,
    req: HttpRequest
) -> Result<HttpResponse, ApiError> {
    debug!("Login attempt for user: {}", login_data.email);
    
    // Find user by email
    let user = match UserService::find_by_email(&login_data.email, &pool).await? {
        Some(user) => user,
        None => {
            debug!("Login failed: User not found with email {}", login_data.email);
            return Err(ApiError::AuthError("Invalid credentials".to_string()));
        },
    };
    
    // Verify password
    let valid = AuthService::verify_password(&login_data.password, &user.password_hash)?;
    if !valid {
        debug!("Login failed: Invalid password for user {}", login_data.email);
        return Err(ApiError::AuthError("Invalid credentials".to_string()));
    }
    
    // Generate JWT token
    let token = AuthService::generate_token(user.user_id, &user.email, &config)?;
    
    // Generate refresh token
    let refresh_token_str = AuthService::generate_refresh_token();
    
    // Store refresh token in database
    AuthService::store_refresh_token(user.user_id, &refresh_token_str, &config, &pool).await?;
    
    // Update last login timestamp
    AuthService::update_last_login(user.user_id, &pool).await?;
    
    info!("User {} logged in successfully", user.email);
    
    // Create login response
    let login_response = LoginResponse {
        token,
        refresh_token: refresh_token_str,
        user_id: user.user_id,
        email: user.email.clone(),
        first_name: user.first_name.clone(),
        last_name: user.last_name.clone(),
    };
    
    // Get IP address from request
    let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_owned());
    
    // Publish login event
    let producer = get_kafka_producer().await;
    let event_publisher = EventPublisher::new(producer);
    
    if let Err(e) = event_publisher.publish_user_login(&login_response, ip_address).await {
        warn!("Failed to publish user login event: {}", e);
    }
    
    // Return login response
    Ok(HttpResponse::Ok().json(login_response))
}

#[post("/refresh-token")]
async fn refresh_token(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    refresh_req: web::Json<serde_json::Value>
) -> Result<HttpResponse, ApiError> {
    let refresh_token_str = match refresh_req.get("refresh_token") {
        Some(token) => token.as_str().ok_or(ApiError::ValidationError("Invalid refresh token".to_string()))?,
        None => return Err(ApiError::ValidationError("Refresh token is required".to_string())),
    };
    
    let conn = pool.get()
        .map_err(|e| {
            error!("Failed to get database connection: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?;
    
    // Find refresh token in database
    let token_str = refresh_token_str.to_string();
    
    // Get a separate connection for the query
    let conn_for_query = pool.get()
        .map_err(|e| {
            error!("Failed to get database connection: {}", e);
            ApiError::DatabaseError(e.to_string())
        })?;
    
    let token_record = web::block(move || {
        use kasoowa::schema::refresh_token::dsl::*;
        let mut conn = conn_for_query;
        refresh_token
            .filter(token.eq(token_str))
            .filter(expires_at.gt(chrono::Utc::now().naive_utc()))
            .first::<RefreshToken>(&mut conn)
            .optional()
    })
    .await
    .map_err(|e| {
        error!("Database operation error: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?
    .map_err(|e| {
        error!("Failed to find refresh token: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?;
    
    let token_record = match token_record {
        Some(record) => record,
        None => return Err(ApiError::AuthError("Invalid or expired refresh token".to_string())),
    };
    
    // Get user from database
    let user = UserService::get_user_by_id(token_record.user_id, &pool).await?;
    
    // Generate new JWT token
    let new_token = AuthService::generate_token(user.user_id, &user.email, &config)?;
    
    // Generate new refresh token
    let new_refresh_token_str = AuthService::generate_refresh_token();
    
    // Store new refresh token in database
    AuthService::store_refresh_token(user.user_id, &new_refresh_token_str, &config, &pool).await?;
    
    // Delete old refresh token
    let old_token = refresh_token_str.to_string();
    
    web::block(move || {
        use kasoowa::schema::refresh_token::dsl::*;
        let mut conn = conn;
        diesel::delete(refresh_token.filter(token.eq(old_token)))
            .execute(&mut conn)
    })
    .await
    .map_err(|e| {
        error!("Database operation error: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?
    .map_err(|e| {
        error!("Failed to delete old refresh token: {}", e);
        ApiError::DatabaseError(e.to_string())
    })?;
    
    info!("Token refreshed for user {}", user.email);
    
    // Return new tokens
    Ok(HttpResponse::Ok().json(json!({
        "token": new_token,
        "refresh_token": new_refresh_token_str,
        "user_id": user.user_id,
        "email": user.email
    })))
}

#[post("/vendor/register")]
async fn register_vendor(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    vendor_data: web::Json<VendorRegistrationRequest>
) -> Result<HttpResponse, ApiError> {
    debug!("Vendor registration attempt for: {}", vendor_data.email);
    
    // Validate terms agreement
    if !vendor_data.agree_to_terms || !vendor_data.agree_to_privacy {
        return Err(ApiError::ValidationError("You must agree to terms and privacy policy".to_string()));
    }
    
    // Check if user already exists
    if let Some(_) = UserService::find_by_email(&vendor_data.email, &pool).await? {
        debug!("Vendor registration failed: Email already exists {}", vendor_data.email);
        return Err(ApiError::ValidationError("Email already exists".to_string()));
    }
    
    // Create user account
    let user_data = CreateUserRequest {
        email: vendor_data.email.clone(),
        password: vendor_data.password.clone(),
        first_name: Some(vendor_data.first_name.clone()),
        last_name: Some(vendor_data.last_name.clone()),
        phone_number: None,
        profile_image: None,
    };
    
    let user_id = UserService::create_user(&user_data, &pool).await?;
    
    // Find vendor role
    let vendor_role = UserService::find_role_by_name("vendor", &pool).await?;
    
    // Assign vendor role
    UserService::assign_role(user_id, vendor_role.role_id, true, &pool).await?;
    
    // Generate JWT token
    let token = AuthService::generate_token(user_id, &vendor_data.email, &config)?;
    
    // Generate refresh token
    let refresh_token_str = AuthService::generate_refresh_token();
    
    // Store refresh token in database
    AuthService::store_refresh_token(user_id, &refresh_token_str, &config, &pool).await?;
    
    info!("Vendor {} registered successfully", vendor_data.email);
    
    // Publish vendor registered event
    let producer = get_kafka_producer().await;
    let event_publisher = EventPublisher::new(producer);
    
    if let Err(e) = event_publisher.publish_vendor_registered(user_id, &vendor_data).await {
        warn!("Failed to publish vendor registered event: {}", e);
    }
    
    // Return registration response
    Ok(HttpResponse::Created().json(json!({
        "success": true,
        "message": "Vendor registered successfully",
        "token": token,
        "refresh_token": refresh_token_str,
        "user_id": user_id,
        "email": vendor_data.email,
        "business_name": vendor_data.business_name
    })))
}

#[post("/affiliate/register")]
async fn register_affiliate(
    pool: web::Data<DbPool>,
    config: web::Data<AppConfig>,
    affiliate_data: web::Json<AffiliateRegistrationRequest>
) -> Result<HttpResponse, ApiError> {
    debug!("Affiliate registration attempt for: {}", affiliate_data.email);
    
    // Validate terms agreement
    if !affiliate_data.agree_to_terms {
        return Err(ApiError::ValidationError("You must agree to terms".to_string()));
    }
    
    // Validate password match
    if affiliate_data.password != affiliate_data.confirm_password {
        return Err(ApiError::ValidationError("Passwords do not match".to_string()));
    }
    
    // Check if user already exists
    if let Some(_) = UserService::find_by_email(&affiliate_data.email, &pool).await? {
        debug!("Affiliate registration failed: Email already exists {}", affiliate_data.email);
        return Err(ApiError::ValidationError("Email already exists".to_string()));
    }
    
    // Extract name components (assuming full_name is "First Last")
    let name_parts: Vec<&str> = affiliate_data.full_name.split_whitespace().collect();
    let first_name = name_parts.first().map(|&s| s.to_string());
    let last_name = if name_parts.len() > 1 {
        Some(name_parts[1..].join(" "))
    } else {
        None
    };
    
    // Create user account
    let user_data = CreateUserRequest {
        email: affiliate_data.email.clone(),
        password: affiliate_data.password.clone(),
        first_name,
        last_name,
        phone_number: Some(affiliate_data.phone_number.clone()),
        profile_image: None,
    };
    
    let user_id = UserService::create_user(&user_data, &pool).await?;
    
    // Find affiliate role
    let affiliate_role = UserService::find_role_by_name("affiliate", &pool).await?;
    
    // Assign affiliate role
    UserService::assign_role(user_id, affiliate_role.role_id, true, &pool).await?;
    
    // Generate JWT token
    let token = AuthService::generate_token(user_id, &affiliate_data.email, &config)?;
    
    // Generate refresh token
    let refresh_token_str = AuthService::generate_refresh_token();
    
    // Store refresh token in database
    AuthService::store_refresh_token(user_id, &refresh_token_str, &config, &pool).await?;
    
    info!("Affiliate {} registered successfully", affiliate_data.email);
    
    // Publish affiliate registered event
    let producer = get_kafka_producer().await;
    let event_publisher = EventPublisher::new(producer);
    
    if let Err(e) = event_publisher.publish_affiliate_registered(user_id, &affiliate_data).await {
        warn!("Failed to publish affiliate registered event: {}", e);
    }
    
    // Return registration response
    Ok(HttpResponse::Created().json(json!({
        "success": true,
        "message": "Affiliate registered successfully",
        "token": token,
        "refresh_token": refresh_token_str,
        "user_id": user_id,
        "email": affiliate_data.email,
        "niche": affiliate_data.niche_name
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables and initialize logger
    dotenvy::dotenv().ok();
    setup_logger();
    
    // Get host and port from environment or use defaults
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a number");
    
    // Connecting to database
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    info!("Connecting to database: {}", db_url);
    
    // Initialize database schema
    let mut conn = PgConnection::establish(&db_url)
        .expect("Failed to establish connection for migrations");
    conn.batch_execute(DB_INIT_SQL)
        .expect("Failed to execute database initialization script");
    info!("Database initialization complete.");
    
    // Set up database connection pool
    let manager = ConnectionManager::<PgConnection>::new(db_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create database connection pool");
    
    // Load and validate configuration
    let config = AppConfig::from_env();
    if let Err(e) = config.validate() {
        error!("Configuration validation error: {}", e);
        panic!("Invalid configuration: {}", e);
    }
    
    // Initialize Kafka producer
    match kasoowa::kafka::create_producer().await {
        Ok(producer) => {
            let _ = KAFKA_PRODUCER.set(Arc::new(producer));
            info!("Kafka producer initialized successfully");
        },
        Err(e) => {
            error!("Failed to initialize Kafka producer: {}", e);
            warn!("Will use dummy producer that logs but doesn't send messages");
            let _ = KAFKA_PRODUCER.set(Arc::new(KafkaProducer::Dummy(DummyKafkaProducer::new())));
        }
    }
    
    // Start Kafka consumers
    let kafka_config = KafkaConfig::from_env();
    if let Ok(mut consumer) = KafkaConsumer::new(&kafka_config) {
        // Subscribe to user events
        if let Err(e) = consumer.subscribe(
            &[kasoowa::kafka::TOPIC_USER_EVENTS], 
            handle_user_event
        ).await {
            error!("Failed to subscribe to user events: {}", e);
        }
        
        // Subscribe to auth events
        if let Err(e) = consumer.subscribe(
            &[kasoowa::kafka::TOPIC_AUTH_EVENTS], 
            handle_auth_event
        ).await {
            error!("Failed to subscribe to auth events: {}", e);
        }
        
        // Subscribe to vendor events
        if let Err(e) = consumer.subscribe(
            &[kasoowa::kafka::TOPIC_VENDOR_EVENTS], 
            handle_vendor_event
        ).await {
            error!("Failed to subscribe to vendor events: {}", e);
        }
        
        // Subscribe to affiliate events
        if let Err(e) = consumer.subscribe(
            &[kasoowa::kafka::TOPIC_AFFILIATE_EVENTS], 
            handle_affiliate_event
        ).await {
            error!("Failed to subscribe to affiliate events: {}", e);
        }
        
        info!("Kafka consumers started successfully");
    } else {
        warn!("Failed to initialize Kafka consumer. Event processing disabled.");
    }
    
    info!("Starting HTTP server at http://{}:{}", host, port);
    
    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Enable request logger middleware
            .wrap(RequestLogger)
            // Register app data
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config.clone()))
            // API routes
            .service(
                web::scope("/api")
                    .service(health_check)
                    .service(list_users)
                    .service(create_user)
                    .service(list_roles)
                    .service(assign_role)
                    .service(login)
                    .service(register_vendor)
                    .service(register_affiliate)
                    .service(refresh_token)
            )
    })
    .workers(2) // Specify number of workers
    .keep_alive(std::time::Duration::from_secs(75)) // Configure keep-alive
    .shutdown_timeout(30) // Graceful shutdown timeout in seconds
    .on_connect(|_conn, addr| {
        info!("New connection from: {:?}", addr);
    })
    .bind((host, port))?
    .run()
    .await
}