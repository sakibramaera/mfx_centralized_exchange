use crate::models::user_model::User;
use crate::utils::auth::Claims;
use crate::utils::auth::{generate_jwt, hash_password, verify_password,send_verification_email};
use jsonwebtoken::{decode, DecodingKey, Validation};
use sqlx::error::ErrorKind;
use sqlx::PgPool;
use std::process::id;
use tokio::task::id as other_id;
use tonic::{metadata::MetadataValue, Request, Response, Status};
use uuid::Uuid;
use user:: user_service_server::{UserService,UserServiceServer};
use user::{SignupRequest, SignupResponse, VerifyEmailRequest, VerifyEmailResponse};
use rand::distributions::{Alphanumeric, Distribution};
use rand::Rng;
use std::time::{Duration, SystemTime};
use chrono::NaiveDateTime;
use chrono::Utc;



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
// Signup API
async fn signup(&self, request: Request<SignupRequest>) -> Result<Response<SignupResponse>, Status> {
    let req = request.into_inner();
    let id = Uuid::new_v4();

    // Validate email or mobile_number
    if req.email.is_empty() && req.mobile_number.is_empty() {
        return Err(Status::invalid_argument("Email or mobile number must be provided"));
    }
    if !req.email.is_empty() && !req.mobile_number.is_empty() {
        return Err(Status::invalid_argument(
            "Either email or mobile number should be provided, not both",
        ));
    }

    // Check if the email or mobile number exists
    if !req.email.is_empty() {
        let existing_email = sqlx::query!("SELECT id FROM users WHERE email = $1", req.email)
            .fetch_optional(&self.db)
            .await
            .map_err(|_| Status::internal("Database error"))?;

        if existing_email.is_some() {
            return Err(Status::already_exists("Email already exists"));
        }
    }

    if !req.mobile_number.is_empty() {
        let existing_mobile_number = sqlx::query!(
            "SELECT id FROM users WHERE mobile_number = $1",
            req.mobile_number
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|_| Status::internal("Database error"))?;

        if existing_mobile_number.is_some() {
            return Err(Status::already_exists("Mobile number already exists"));
        }
    }

        let password_hash = hash_password(&req.password)
            .map_err(|_| Status::internal("Failed to hash password"))?;

        // let role = if req.role.is_empty() {
        //     "user"
        // } else {
        //     &req.role
        // };

    sqlx::query!(
        "INSERT INTO users (id, email, mobile_number, password, created_at) 
         VALUES ($1, $2, $3, $4, NOW())",
        id,
        req.email,
        req.mobile_number,
        password_hash,
    )
    .execute(&self.db)
    .await
    .map_err(|e| {
        eprintln!("Failed to create user: {:?}", e);
        Status::internal("Failed to create user")
    })?;

    // Generate random verification code
    let verification_code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    // Save the verification code and expiration time in the `email_verifications` table
    let expiration_time = SystemTime::now() + Duration::new(15 * 60, 0); // 15 minutes expiration
    let naive_expiration_time = expiration_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| NaiveDateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos()))
        .unwrap();

    sqlx::query!(
        "INSERT INTO email_verifications (id, email, verification_code, expiration_time) 
         VALUES ($1, $2, $3, $4)",
        Uuid::new_v4(),
        req.email,
        verification_code,
        naive_expiration_time
    )
    .execute(&self.db)
    .await
    .map_err(|e| {
        eprintln!("Error inserting verification code: {:?}", e);
        Status::internal("Failed to store verification code")
    })?;

    // Send the verification email (You can replace `send_verification_email` with your email service)
    send_verification_email(&req.email, &verification_code)
        .await
        .map_err(|_| Status::internal("Failed to send verification email"))?;

    Ok(Response::new(SignupResponse {
        message: "Verification code sent to email".to_string(),
        id: id.to_string(),
    }))
}

async fn verify_email(
    &self,
    request: Request<VerifyEmailRequest>,
) -> Result<Response<VerifyEmailResponse>, Status> {
    let req = request.into_inner();

    // Fetch the email and expiration time from the email_verifications table using the verification code
    let verification = sqlx::query!(
        "SELECT email, expiration_time FROM email_verifications WHERE verification_code = $1",
        req.verification_code
    )
    .fetch_optional(&self.db)
    .await
    .map_err(|_| Status::internal("Database error"))?;

    match verification {
        Some(v) => {
            // Get the current SystemTime and convert it to NaiveDateTime
            let current_time = SystemTime::now();
            let naive_current_time = current_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| NaiveDateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos()))
                .unwrap();

            // Compare the current time with the expiration time
            if naive_current_time < v.expiration_time {
                let email = v.email; // ✅ Email received

                // Fetch the user data by email from the users table
                let user_data = sqlx::query!(
                    "SELECT id, email, password, mobile_number FROM users WHERE email = $1",
                    email
                )
                .fetch_optional(&self.db)
                .await
                .map_err(|_| Status::internal("Database error"))?;

                match user_data {
                    Some(mut user) => {
                        // User exists, mark as verified
                        sqlx::query!(
                            "UPDATE users SET is_verified = $1 WHERE id = $2",
                            true, // Mark user as verified
                            user.id
                        )
                        .execute(&self.db)
                        .await
                        .map_err(|_| Status::internal("Failed to update user verification status"))?;

                        // Generate JWT
                        let role = "user".to_string(); // Default role (or fetch from user data)
                        let token = generate_jwt(&user.id, &self.jwt_secret, &role)
                            .map_err(|e| Status::internal(format!("Failed to generate token: {}", e)))?;

                        Ok(Response::new(VerifyEmailResponse {
                            message: "User signUp successfully".to_string(),
                            token,
                        }))
                    }
                    None => Err(Status::not_found("User not found")),
                }
            } else {
                Err(Status::invalid_argument("Invalid or expired verification code"))
            }
        }
        None => Err(Status::not_found("Verification code not found")),
    }
}

}

pub fn get_user_service(db: PgPool, jwt_secret: String) -> UserServiceServer<UserServiceImpl> {
    UserServiceServer::new(UserServiceImpl::new(db, jwt_secret))
}
