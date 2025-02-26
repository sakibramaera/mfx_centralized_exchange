use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OsRng; // Import OsRng from rand_core
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use lettre::message::{SinglePart, header};
use std::error::Error;
// use tokio::runtime::Runtime;


#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // Expiry timestamp
    pub role: String, // Role (admin/user)
    pub exp: usize,   // Expiry timestamp
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng); // Use rand_core::OsRng here
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "Failed to hash password".to_string())
}

pub fn verify_password(stored_hash: &str, password: &str) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(stored_hash).map_err(|_| "Invalid hash format")?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map(|_| true)
        .map_err(|_| "Password does not match".to_string())
}

pub fn generate_jwt(user_id: &Uuid,role: &str, secret: &str) -> Result<String, String> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| "Failed to generate JWT".to_string())
}

pub async fn send_verification_email(email: &str, verification_code: &str) -> Result<(), Box<dyn Error>> {
    // Create the email message
    let email = Message::builder()
        .from("sakibansari1115@gmail.com".parse()?)
        .to(email.parse()?)
        .subject("Email Verification Code")
        .header(header::ContentType::TEXT_PLAIN)
        .body(format!(
            "Your verification code is: {}",
            verification_code
        ))?;

    // Set up the SMTP transport
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(Credentials::new(
            "sakibansari1115@gmail.com".to_string(),
            "dgng skwd pism zlgl".to_string(),
        ))
        .build();

    // Use tokio runtime to send the email asynchronously
    // let rt = Runtime::new()?;
    // rt.block_on(async {
        // Send the email asynchronously
        mailer.send(&email).map(|_| ()).map_err(|e| {
            eprintln!("Error sending email: {:?}", e); // Log detailed error
            Box::new(e) as Box<dyn Error> // Return the error
        })
    // })
}


