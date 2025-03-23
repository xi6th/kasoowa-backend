-- Drop tables in reverse order of creation to avoid foreign key constraints

-- First drop tables with foreign key dependencies
DROP TABLE IF EXISTS admin_session;
DROP TABLE IF EXISTS refresh_token;
DROP TABLE IF EXISTS user_role;
DROP TABLE IF EXISTS admin;

-- Then drop the base tables
DROP TABLE IF EXISTS user_account;
DROP TABLE IF EXISTS role_type;
DROP TABLE IF EXISTS admin_role_type;