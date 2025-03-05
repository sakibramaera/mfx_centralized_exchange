use crate::models::user_model::User;
// use crate::utils::auth::Claims;
use crate::utils::auth::{generate_jwt, hash_password,
    verify_password,send_verification_email, 
    send_verification_sms,generate_otp,
    generate_totp_secret,generate_qr_code,generate_totp_uri,store_otp,get_stored_otp};
// use jsonwebtoken::{decode, DecodingKey, Validation};
// use sqlx::error::ErrorKind;
use sqlx::PgPool;
// use std::process::id;
// use tokio::task::id as other_id;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use user:: user_service_server::{UserService,UserServiceServer};
use user::{SignupRequest, SignupResponse,
    LoginRequest,LoginResponse,
    VerifyUserRequest,VerifyUserResponse,
    ResendVerificationRequest,ResendVerificationResponse,
    VerifyOtpRequest, VerifyOtpResponse,
};
// use rand::distributions::{Alphanumeric};
// use rand::Rng;
// use std::time::{Duration, SystemTime};
// use chrono::NaiveDateTime;
use chrono::Utc;
use totp_rs::{TOTP, Algorithm, Secret};
use redis::AsyncCommands;
extern crate data_encoding;
use data_encoding::BASE32;
use base32::Alphabet;
use std::str;
use google_authenticator::GoogleAuthenticator;


// use std::error::Error;

pub mod user {
    tonic::include_proto!("user");
}
pub struct UserServiceImpl {
    pub db: PgPool,
    pub jwt_secret: String,
}
impl UserServiceImpl {
    pub fn new(db: PgPool, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
    }
}

#[tonic::async_trait]
impl UserService for UserServiceImpl {
// Signup 
async fn signup(&self, request: Request<SignupRequest>) -> Result<Response<SignupResponse>, Status> {
    let req = request.into_inner();
    let id = Uuid::new_v4();

    // Ensure at least one of email or mobile_number is provided
    if req.email.is_empty() && req.mobile_number.is_empty() {
            return Err(Status::invalid_argument("Email or mobile number must be provided"));
        }
    if !req.email.is_empty() && !req.mobile_number.is_empty() {
            return Err(Status::invalid_argument("Provide either email or mobile number, not both"));
        }

    // Check if email or mobile number already exists
    if let Some(existing) = sqlx::query!(
        "SELECT email, mobile_number FROM users WHERE 
         (email = $1 AND $1 IS NOT NULL) OR 
         (mobile_number = $2 AND $2 IS NOT NULL)",
        if req.email.is_empty() { None } else { Some(req.email.clone()) },
        if req.mobile_number.is_empty() { None } else { Some(req.mobile_number.clone()) }
    )
    .fetch_optional(&self.db)
    .await
    .map_err(|_| Status::internal("Database error"))? 
    {
        if !req.email.is_empty() && existing.email == Some(req.email.clone()) {
            return Err(Status::already_exists("Email already exists"));
        }
        if !req.mobile_number.is_empty() && existing.mobile_number == Some(req.mobile_number.clone()) {
            return Err(Status::already_exists("Mobile number already exists"));
        }
    }

    // Hash the password
    let password_hash = hash_password(&req.password)
        .map_err(|_| Status::internal("Failed to hash password"))?;

    // Insert user into database
    let insert_result = sqlx::query!(
        "INSERT INTO users (id, email, mobile_number, password, is_verified, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
        id,
        if req.email.is_empty() { None } else { Some(req.email.clone()) }, // Ensure NULL if empty
        if req.mobile_number.is_empty() { None } else { Some(req.mobile_number.clone()) }, // Ensure NULL if empty
        password_hash,
        false
    )
    .execute(&self.db)
    .await;

    // Handle duplicate key error properly
    if let Err(e) = insert_result {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23505") {
                return Err(Status::already_exists("Email or mobile number already exists"));
            }
        }
        eprintln!("Failed to create user: {:?}", e);
        return Err(Status::internal("Failed to create user"));
    }

    let verification_code = generate_otp();
    let expiration_timestamp = Utc::now().naive_utc() + chrono::Duration::minutes(5);

    // ✅ Insert verification record using `identifier`
    sqlx::query!(
        "INSERT INTO user_verifications (user_id, identifier, verification_code, expiration_time) 
         VALUES ($1, $2, $3, $4)",
        id,
        if !req.email.is_empty() { req.email.clone() } else { req.mobile_number.clone() }, // Store email or mobile in `identifier`
        verification_code,
        expiration_timestamp
    )
    .execute(&self.db)
    .await
    .map_err(|_| Status::internal("Failed to store verification code"))?;

    // ✅ Send verification code (Email or SMS)
    if !req.email.is_empty() {
        send_verification_email(&req.email, &verification_code)
            .await
            .map_err(|_| Status::internal("Failed to send verification email"))?;
    } else {
        send_verification_sms(&req.mobile_number, &verification_code)
            .await
            .map_err(|_| Status::internal("Failed to send verification SMS"))?;
    }

    Ok(Response::new(SignupResponse {
        message: "Verification code sent".to_string(),
        id: id.to_string(),
    }))
}

async fn resend_verification_code(&self,request: Request<ResendVerificationRequest>,) -> Result<Response<ResendVerificationResponse>, Status> {
    let req = request.into_inner();
    let identifier = req.identifier.clone();

    // Check if the user exists
    let user = sqlx::query!(
        "SELECT id, email, mobile_number, is_verified FROM users WHERE email = $1 OR mobile_number = $1",
        identifier
    )
    .fetch_optional(&self.db)
    .await
    .map_err(|_| Status::internal("Database query error"))?;

    let user = match user {
        Some(user) => user,
        None => return Err(Status::not_found("User not found")),
    };

    // Ensure the user is not already verified
    if user.is_verified.unwrap_or(false) {
        return Err(Status::already_exists("User is already verified"));
    }

    // Generate a new verification code
    let new_verification_code = generate_otp();
    let expiration_timestamp = Utc::now().naive_utc() + chrono::Duration::minutes(5);

    // Check if a verification record exists for the user
    let existing_verification = sqlx::query!(
        "SELECT id FROM user_verifications WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&self.db)
    .await
    .map_err(|_| Status::internal("Failed to check existing verification record"))?;

    if let Some(_) = existing_verification {
        // Update existing verification record
        sqlx::query!(
            "UPDATE user_verifications SET verification_code = $1, expiration_time = $2 WHERE user_id = $3",
            new_verification_code,
            expiration_timestamp,
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::internal("Failed to update verification code"))?;
    } else {
        // Insert new verification record
        sqlx::query!(
            "INSERT INTO user_verifications (user_id, verification_code, expiration_time) VALUES ($1, $2, $3)",
            user.id,
            new_verification_code,
            expiration_timestamp
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::internal("Failed to insert new verification code"))?;
    }

    // Simulate sending the verification code (Replace with actual email/SMS service)
    println!(
        "Verification code sent to {}: {}",
        identifier, new_verification_code
    );

     if !req.identifier.is_empty() {
        send_verification_email(&req.identifier, &new_verification_code)
            .await
            .map_err(|_| Status::internal("Failed to send verification email"))?;
    } else {
        send_verification_sms(&req.identifier, &new_verification_code)
            .await
            .map_err(|_| Status::internal("Failed to send verification SMS"))?;
    }
    // Response
    let response = ResendVerificationResponse {
        success: true,
        message: "Verification code resent successfully".to_string(),
    };
    Ok(Response::new(response))
}

async fn verify_user(&self, request: Request<VerifyUserRequest>) -> Result<Response<VerifyUserResponse>, Status> {
    let req = request.into_inner();

    use uuid::Uuid; // Ensure Uuid is imported

    let user_id = Uuid::parse_str(&req.user_id)
    .map_err(|_| Status::invalid_argument("Invalid user_id format"))?;


    // Fetch user_id and expiration_time from `user_verifications`
    let verification = sqlx::query!(
        "SELECT user_id, expiration_time FROM user_verifications WHERE verification_code = $1 AND user_id = $2",
        req.verification_code,
        user_id
    )
    .fetch_optional(&self.db)
    .await
    .map_err(|_| Status::internal("Database error"))?;

    match verification {
        Some(v) => {
            let naive_current_time = Utc::now().naive_utc();
            if naive_current_time > v.expiration_time {
                return Err(Status::invalid_argument("Verification code expired"));
            }

            // Update user verification status
            sqlx::query!(
                "UPDATE users SET is_verified = true WHERE id = $1",
                v.user_id
            )
            .execute(&self.db)
            .await
            .map_err(|_| Status::internal("Failed to update user verification status"))?;

            // Remove verification record
            sqlx::query!(
                "DELETE FROM user_verifications WHERE verification_code = $1 AND user_id = $2",
                req.verification_code,
                user_id
            )
            .execute(&self.db)
            .await
            .map_err(|_| Status::internal("Failed to remove verification code"))?;

            // Generate JWT token
            let token = generate_jwt(&v.user_id, &self.jwt_secret, "user")
                .map_err(|_| Status::internal("Failed to generate token"))?;

            Ok(Response::new(VerifyUserResponse {
                message: "User verified and signUp successfully".to_string(),
                token,
            }))
        }
        None => Err(Status::not_found("Invalid verification code")),
    }
}
// Login API
async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();

         // ✅ Determine which identifier is provided
            let identifier = if !req.email.is_empty() {
                req.email
                }else if !req.mobile_number.is_empty() {
                req.mobile_number
                } else {
                return Err(Status::invalid_argument("Please provide email or mobile number."));
                };

        // ✅ Fetch user by email, or mobile number
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, password, mobile_number, role , is_verified, is_2fa_enabled, totp_secret 
            FROM users WHERE email = $1 OR mobile_number = $1",
            identifier 
        )
        .fetch_optional(&self.db) // ✅ Better error handling
        .await
        .map_err(|_| Status::internal("Database error"))?; 

        // ✅ If user not found, return error
        let mut user = user.ok_or_else(|| Status::unauthenticated("Email does not exist. Please sign up first.."))?;

        // ✅ Verify password
        match verify_password(&user.password, &req.password) {
        Ok(true) => {}, // Password matches, continue
        _ => return Err(Status::unauthenticated("Login failed. Please check your credentials.")),
        }

        if !user.is_verified.unwrap_or(false) {
        return Err(Status::permission_denied("User not verified"));
        }

        // ✅ If 2FA is not enabled, generate a TOTP secret and enable it
    let totp_secret = if user.is_2fa_enabled.unwrap_or(false) {
        user.totp_secret.clone().unwrap()
    } else {
        let new_secret = generate_totp_secret();
        sqlx::query!(
            "UPDATE users SET is_2fa_enabled = TRUE, totp_secret = $1 WHERE id = $2",
            new_secret,
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|_| Status::internal("Failed to enable 2FA."))?;

        user.is_2fa_enabled = Some(true);
        user.totp_secret = Some(new_secret.clone());
         // ✅ Google Authenticator QR Code ke liye URI Generate Karein
        let totp_uri = generate_totp_uri(&user.email.clone().unwrap(), &new_secret);

        // ✅ QR Code generate karke file save karein
        let qr_code_path = format!("./qr_codes/{}.png", user.id);
        generate_qr_code(&totp_uri, &qr_code_path).await.unwrap();
        new_secret
    };

    // ✅ Step 1: Generate Email OTP
    let email_otp = generate_otp();
    let email = user.email.clone().unwrap_or_default();
    send_verification_email(&email, &email_otp).await;

    store_otp(&email, &email_otp).await.ok();
    
    // ✅ Send response to user
    Ok(Response::new(LoginResponse {
        message: "OTP sent. Scan QR code to setup Google Authenticator.".to_string(),
        id: user.id.to_string(),
        qr_code_url: format!("/qr_codes/{}.png", user.id),  
        token: "".to_string(), 
    }))

    }

async fn verify_otp(&self, request: Request<VerifyOtpRequest>) -> Result<Response<VerifyOtpResponse>, Status> {
    let req = request.into_inner();

   
    let user_id = Uuid::parse_str(&req.user_id)
        .map_err(|_| Status::invalid_argument("Invalid user ID format"))?;

    // ✅ User fetch kare ID se
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, password, mobile_number, role, is_verified, is_2fa_enabled, totp_secret FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&self.db)
    .await
    .map_err(|_| Status::internal("Database error"))?
    .ok_or_else(|| Status::unauthenticated("User not found"))?;

    let totp_secret = user
        .totp_secret
        .clone()
        .ok_or_else(|| Status::internal("TOTP secret not found"))?;

    println!("📌 TOTP Secret from DB: {:?}", totp_secret);

      // ✅ Verify TOTP Code (GoogleAuthenticator)
    let auth = GoogleAuthenticator::new();
    let time_slice = Utc::now().timestamp() as u64 / 30;
    let is_totp_valid = auth.verify_code(&totp_secret, &req.totp_code, 3, time_slice);

    println!("🛠 TOTP Verification Result: {}", is_totp_valid);

    if !is_totp_valid {
        return Err(Status::unauthenticated("❌ Invalid Google Authenticator Code!"));
    }


    // ✅ Email OTP verify kare (Redis se fetch karein)
    let stored_otp = get_stored_otp(&user.email.clone().unwrap()).await
        .map_err(|_| Status::internal("Failed to fetch OTP from Redis"))?;

    if stored_otp.is_none() || stored_otp.as_deref() != Some(&req.email_otp) {
        return Err(Status::unauthenticated("Invalid Email OTP"));
    }

    // ✅ OTP verify hone ke baad Redis se delete karein (Security best practice)
    let client = redis::Client::open("redis://127.0.0.1/").map_err(|_| Status::internal("Redis connection failed"))?;
    let mut con = client.get_async_connection().await.map_err(|_| Status::internal("Redis connection error"))?;
    let _: () = con.del(format!("otp:{}", user.email.clone().unwrap())).await.map_err(|_| Status::internal("Failed to delete OTP"))?;

    // ✅ Dono OTP pass ho gaye toh JWT token generate kare
    let token = generate_jwt(&user.id, user.role.as_deref().unwrap_or("user"), &self.jwt_secret)
        .map_err(|_| Status::internal("Failed to generate JWT"))?;

    Ok(Response::new(VerifyOtpResponse {
        message: "Login successful".to_string(),
        token,
    }))
}


}

pub fn get_user_service(db: PgPool, jwt_secret: String) -> UserServiceServer<UserServiceImpl> {
    UserServiceServer::new(UserServiceImpl::new(db, jwt_secret))
}
