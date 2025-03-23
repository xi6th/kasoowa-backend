-- Create tables for authentication and authorization

-- User Management Tables
CREATE TABLE user_account (
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

CREATE TABLE role_type (
  role_id SERIAL PRIMARY KEY,
  role_name VARCHAR(50) UNIQUE NOT NULL,
  description VARCHAR(255)
);

CREATE TABLE user_role (
  user_id INTEGER NOT NULL,
  role_id INTEGER NOT NULL,
  assigned_date TIMESTAMP NOT NULL DEFAULT NOW(),
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE admin (
  admin_id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  role_type_id INTEGER NOT NULL,
  last_login TIMESTAMP,
  permission_level INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE admin_role_type (
  role_type_id SERIAL PRIMARY KEY,
  role_name VARCHAR(50) UNIQUE NOT NULL,
  description VARCHAR(255)
);


-- Create password_reset table
CREATE TABLE IF NOT EXISTS password_reset (
    reset_id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    is_used BOOLEAN NOT NULL DEFAULT FALSE
);

-- Create category table
CREATE TABLE IF NOT EXISTS category (
    category_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    parent_id INTEGER REFERENCES category(category_id)
);

-- Create product table
CREATE TABLE IF NOT EXISTS product (
    product_id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    category_id INTEGER NOT NULL,
    image_url VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    stock_quantity INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (category_id) REFERENCES category(category_id)
);

-- Create product_variant table
CREATE TABLE IF NOT EXISTS product_variant (
    variant_id SERIAL PRIMARY KEY,
    product_id INTEGER NOT NULL,
    weight VARCHAR(50) NOT NULL,
    size VARCHAR(50) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock_quantity INTEGER NOT NULL DEFAULT 0,
    variant_image VARCHAR(255),
    FOREIGN KEY (product_id) REFERENCES product(product_id) ON DELETE CASCADE
);

-- Insert initial roles
INSERT INTO role_type (role_name, description) VALUES 
('customer', 'Regular customer with basic privileges'),
('vendor', 'Seller with product management privileges'),
('affiliate', 'Affiliate partner with promotional privileges');

-- Insert initial admin roles
INSERT INTO admin_role_type (role_name, description) VALUES 
('super_admin', 'Full system access with all privileges'),
('support_admin', 'Customer support with limited admin privileges'),
('moderator', 'Content moderation privileges');

-- Add foreign keys
ALTER TABLE user_role ADD CONSTRAINT fk_user_role_user
FOREIGN KEY (user_id) REFERENCES user_account(user_id) ON DELETE CASCADE;

ALTER TABLE user_role ADD CONSTRAINT fk_user_role_role
FOREIGN KEY (role_id) REFERENCES role_type(role_id) ON DELETE CASCADE;

ALTER TABLE admin ADD CONSTRAINT fk_admin_role_type
FOREIGN KEY (role_type_id) REFERENCES admin_role_type(role_type_id) ON DELETE RESTRICT;

-- Create refresh token table for JWT authentication
CREATE TABLE refresh_token (
  token_id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  FOREIGN KEY (user_id) REFERENCES user_account(user_id) ON DELETE CASCADE
);

-- Create admin session table
CREATE TABLE admin_session (
  session_id SERIAL PRIMARY KEY,
  admin_id INTEGER NOT NULL,
  session_token VARCHAR(255) NOT NULL,
  ip_address VARCHAR(50),
  user_agent VARCHAR(255),
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  FOREIGN KEY (admin_id) REFERENCES admin(admin_id) ON DELETE CASCADE
);