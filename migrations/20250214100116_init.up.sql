-- Add up migration script here
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE,
    mobile_number VARCHAR(20) UNIQUE,
    password TEXT NOT NULL,
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    is_verified BOOLEAN DEFAULT FALSE,
    is_2fa_enabled BOOLEAN DEFAULT FALSE, -- ✅ 2FA enabled or not
    totp_secret TEXT,                     -- ✅ Google Authenticator Secret
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE user_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identifier TEXT NOT NULL, -- Can be email or mobile number
    verification_code TEXT NOT NULL UNIQUE,
    expiration_time TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
