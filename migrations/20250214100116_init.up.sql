-- Add up migration script here
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE,
    mobile_number VARCHAR(20),
    password TEXT NOT NULL,
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    is_verified BOOLEAN DEFAULT FALSE, -- Field to track email verification status 
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Add email verification table
CREATE TABLE email_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    verification_code VARCHAR(10) NOT NULL,
    expiration_time TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes'),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'expired')), -- Track the status of the verification
    created_at TIMESTAMP DEFAULT NOW()
);


