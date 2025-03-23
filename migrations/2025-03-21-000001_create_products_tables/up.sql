-- Add these migrations to your database setup script in main.rs

-- Create product tables
CREATE TABLE IF NOT EXISTS category (
    category_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    parent_id INTEGER REFERENCES category(category_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS product (
    product_id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES user_account(user_id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    price FLOAT8 NOT NULL,
    category_id INTEGER NOT NULL REFERENCES category(category_id) ON DELETE RESTRICT,
    image_url VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    stock_quantity INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS product_variant (
    variant_id SERIAL PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES product(product_id) ON DELETE CASCADE,
    weight VARCHAR(50) NOT NULL,
    size VARCHAR(50) NOT NULL,
    price FLOAT8 NOT NULL,
    stock_quantity INTEGER NOT NULL DEFAULT 0,
    variant_image VARCHAR(255)
);

-- Create password reset table
CREATE TABLE IF NOT EXISTS password_reset (
    reset_id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    is_used BOOLEAN NOT NULL DEFAULT FALSE
);

-- Insert some default categories
INSERT INTO category (name, description) VALUES 
    ('Electronics', 'Electronic devices and accessories'),
    ('Clothing', 'Apparel and fashion items'),
    ('Home & Garden', 'Products for home and garden'),
    ('Beauty & Personal Care', 'Beauty products and personal care items'),
    ('Books', 'Books and publications'),
    ('Sports & Outdoors', 'Sports equipment and outdoor gear'),
    ('Toys & Games', 'Toys, games, and entertainment items'),
    ('Health & Wellness', 'Health supplements and wellness products'),
    ('Jewelry', 'Jewelry and watches'),
    ('Automotive', 'Automotive parts and accessories')
ON CONFLICT (name) DO NOTHING;

-- Create index on product for faster lookups by vendor
CREATE INDEX IF NOT EXISTS idx_product_vendor_id ON product(vendor_id);

-- Create index on password reset for faster token lookups
CREATE INDEX IF NOT EXISTS idx_password_reset_token ON password_reset(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_email ON password_reset(email);