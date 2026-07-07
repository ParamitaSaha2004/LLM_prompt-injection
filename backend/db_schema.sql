CREATE DATABASE IF NOT EXISTS promptshield;
USE promptshield;

-- Drop tables if they exist (clean setup)
DROP TABLE IF EXISTS attack_logs;
DROP TABLE IF EXISTS chat_messages;
DROP TABLE IF EXISTS conversations;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS users;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user', -- 'user' or 'admin'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Documents table
CREATE TABLE documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    status VARCHAR(50) DEFAULT 'processed', -- 'processing', 'processed', 'failed'
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Conversations table
CREATE TABLE conversations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Chat messages table
CREATE TABLE chat_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    conversation_id INT NOT NULL,
    sender VARCHAR(20) NOT NULL, -- 'user' or 'assistant'
    message TEXT NOT NULL,
    risk_score INT DEFAULT 0,
    is_blocked BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Attack logs table
CREATE TABLE attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL, -- Nullable for unauthenticated or system test injections
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attack_type VARCHAR(100) NOT NULL, -- 'Direct Injection', 'Indirect Injection', 'Payload Splitting', etc.
    payload TEXT NOT NULL,
    risk_score INT NOT NULL,
    severity VARCHAR(20) NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
    decision VARCHAR(20) NOT NULL, -- 'Allowed', 'Blocked'
    explanation TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Seed initial admin user (username: admin, password: adminpassword (hash will be set dynamically via script or default hash))
-- Seed initial user (username: demo_user, password: userpassword)
