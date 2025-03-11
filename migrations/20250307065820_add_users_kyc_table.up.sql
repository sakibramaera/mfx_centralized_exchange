-- Add up migration script here
CREATE TABLE users_kyc (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    dob DATE NOT NULL,
    address TEXT NOT NULL,
    document_type TEXT CHECK (document_type IN ('passport', 'id_card', 'driver_license')),
    document_url TEXT NOT NULL,
    face_scan_url TEXT,
    kyc_status TEXT DEFAULT 'pending' CHECK (kyc_status IN ('pending', 'approved', 'rejected')),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
