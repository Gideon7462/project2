--creating the database
CREATE DATABASE TENANT_DATABASE;
USE TENANT_DATABASE;

-- Users Table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    last_login TIMESTAMP,  -- Using TIMESTAMP for timezone support
    is_admin BOOLEAN DEFAULT 0  -- 1 for admin, 0 for normal user
);tenant_database

-- Authentication Logs Table
CREATE TABLE auth_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    login_time TIMESTAMP NOT NULL,
    ip_address VARCHAR(100) NOT NULL,
    device_fingerprint VARCHAR(255),
    status ENUM('Success', 'Failure') NOT NULL,  -- Restricted to predefined values
    INDEX(user_id),
    INDEX(device_fingerprint),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- OTP Codes Table
CREATE TABLE otp_codes (
    otp_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT 0,  -- 0 = Not used, 1 = Used
    UNIQUE(user_id, otp_code),  -- Prevent duplicate OTP codes for the same user
    INDEX(user_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Admin Actions Table
CREATE TABLE admin_actions (
    action_id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT NOT NULL,
    action_description TEXT NOT NULL,
    action_time TIMESTAMP NOT NULL,
    INDEX(admin_id),
    FOREIGN KEY (admin_id) REFERENCES users(user_id) ON DELETE CASCADE
);
