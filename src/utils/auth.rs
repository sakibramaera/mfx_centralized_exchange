use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OsRng; // Import OsRng from rand_core
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use lettre::message::{header};
use std::error::Error;
// use tokio::runtime::Runtime;
use reqwest::Client;
// use serde_json::json;
use crate::env;
use rand::Rng;
use totp_rs::{TOTP, Algorithm};
use base32::Alphabet;
// use base32::encode;
use qrcode::QrCode;
use qrcode::render::unicode;
use redis::AsyncCommands;
use google_authenticator::GoogleAuthenticator;
use google_authenticator::ErrorCorrectionLevel;
// use qrcode::QrCode;
// use image::Luma;


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

pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let otp: u32 = rng.gen_range(100_000..1_000_000); // Ensures 6-digit OTP
    otp.to_string()
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

pub async fn send_verification_sms(mobile_number: &str, verification_code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let account_sid = env::var("TWILIO_ACCOUNT_SID")?;
    let auth_token = env::var("TWILIO_AUTH_TOKEN")?;
    let from_number = env::var("TWILIO_PHONE_NUMBER")?; // ✅ Twilio verified phone number

    let url = format!("https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json", account_sid);

    let client = Client::new();
    let params = [
        ("To", mobile_number),
        ("From", &from_number), // ✅ Twilio number use kar rahe hain
        ("Body", &format!("Your verification code is: {}", verification_code)),
    ];

    let res = client.post(&url)
        .basic_auth(&account_sid, Some(&auth_token))
        .form(&params)
        .send()
        .await?;

    let status = res.status();  // ✅ Status ko pehle store kar lo
    let response_text = res.text().await?;  // ✅ Ab response body extract karo

    if status.is_success() {
        println!("✅ SMS sent successfully to {}", mobile_number);
        Ok(())
    } else {
        eprintln!("❌ Twilio API Error: Status: {}, Response: {}", status, response_text);
        Err(response_text.into())
    }

}

pub fn generate_totp_secret() -> String {
    let auth = GoogleAuthenticator::new();
    auth.create_secret(32) // 32-character long base32 secret
}

pub async fn generate_qr_code(user_email: &str, secret: &str) -> Result<(), Box<dyn Error>> {
    let auth = GoogleAuthenticator::new();

    // Generate Google Authenticator-compatible OTP Auth URI
    let otp_auth_url = auth.qr_code_url(secret, user_email, "MyApp", 200, 200, ErrorCorrectionLevel::Medium);

    // Generate QR code from the URL
    let code = QrCode::new(otp_auth_url)?;
    let image = code.render::<unicode::Dense1x2>().build();

    println!("📷 Scan this QR code:\n{}", image);
    Ok(())
}

pub fn generate_totp_uri(secret: &str, email: &str) -> String {
    format!(
        "otpauth://totp/MyApp:{}?secret={}&issuer=MyApp&algorithm=SHA1&digits=6&period=30",
        email, secret
    )
}

pub async fn store_otp(email: &str, otp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = redis::Client::open("redis://127.0.0.1/")?;
    let mut con = client.get_async_connection().await?;
    con.set_ex(format!("otp:{}", email), otp, 300).await?; // 300 seconds (5 minutes expiry)
    Ok(())
}

pub async fn get_stored_otp(email: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let client = redis::Client::open("redis://127.0.0.1/")?; // Redis se connect karein
    let mut con = client.get_async_connection().await?;
    
    let otp: Option<String> = con.get(format!("otp:{}", email)).await?;
    Ok(otp)
}
