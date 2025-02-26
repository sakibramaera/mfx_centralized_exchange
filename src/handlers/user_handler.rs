use crate::models::user_model::User;
use crate::utils::auth::Claims;
use crate::utils::auth::{generate_jwt, hash_password, verify_password,send_verification_email, send_verification_sms,generate_otp};
use jsonwebtoken::{decode, DecodingKey, Validation};
use sqlx::error::ErrorKind;
use sqlx::PgPool;
use std::process::id;
use tokio::task::id as other_id;
use tonic::{metadata::MetadataValue, Request, Response, Status};
use uuid::Uuid;
use user:: user_service_server::{UserService,UserServiceServer};
use user::{SignupRequest, SignupResponse,
    LoginRequest,LoginResponse,
    VerifyUserRequest,VerifyUserResponse,
    ResendVerificationRequest,ResendVerificationResponse, 
};
use rand::distributions::{Alphanumeric, Distribution};
use rand::Rng;
use std::time::{Duration, SystemTime};
use chrono::NaiveDateTime;
use chrono::Utc;
use std::error::Error;

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
    let expiration_timestamp = Utc::now().naive_utc() + chrono::Duration::minutes(15);

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
    let expiration_timestamp = Utc::now().naive_utc() + chrono::Duration::minutes(15);

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

    // Fetch user_id and expiration_time from `user_verifications`
    let verification = sqlx::query!(
        "SELECT user_id, expiration_time FROM user_verifications WHERE verification_code = $1",
        req.verification_code
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
                "DELETE FROM user_verifications WHERE verification_code = $1",
                req.verification_code
            )
            .execute(&self.db)
            .await
            .map_err(|_| Status::internal("Failed to remove verification code"))?;

            // Generate JWT token
            let token = generate_jwt(&v.user_id, &self.jwt_secret, "user")
                .map_err(|_| Status::internal("Failed to generate token"))?;

            Ok(Response::new(VerifyUserResponse {
                message: "User verified successfully".to_string(),
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
            "SELECT id, email, password, mobile_number, role , is_verified
            FROM users WHERE email = $1 OR mobile_number = $1",
            identifier 
        )
        .fetch_optional(&self.db) // ✅ Better error handling
        .await
        .map_err(|_| Status::internal("Database error"))?; 

        // ✅ If user not found, return error
        let user = user.ok_or_else(|| Status::unauthenticated("Email does not exist. Please sign up first.."))?;

        // ✅ Verify password
        match verify_password(&user.password, &req.password) {
        Ok(true) => {}, // Password matches, continue
        _ => return Err(Status::unauthenticated("Login failed. Please check your credentials.")),
        }

        if !user.is_verified.unwrap_or(false) {
        return Err(Status::permission_denied("User not verified"));
        }

        // ✅ Generate JWT token
        let token = generate_jwt(&user.id,user.role.as_deref().unwrap_or("user"),&self.jwt_secret)
            .map_err(|_| Status::internal("Failed to generate JWT"))?;

        // ✅ Return response
        Ok(Response::new(LoginResponse {
            message: "User login successfully".to_string(),
            id: user.id.to_string(),
            token: token.clone(),
        }))
    }

}

pub fn get_user_service(db: PgPool, jwt_secret: String) -> UserServiceServer<UserServiceImpl> {
    UserServiceServer::new(UserServiceImpl::new(db, jwt_secret))
}
