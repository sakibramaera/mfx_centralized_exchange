use serde::{Deserialize, Serialize};
// use sqlx::FromRow;
use uuid::Uuid;

#[derive(sqlx::FromRow, Serialize, Deserialize)]
pub struct Auth {
    pub id: Uuid,
    pub email: Option<String>,
    pub password: String,
    pub mobile_number: Option<String>,
    pub role: Option<String>,
    pub is_verified: Option<bool>,
    pub is_2fa_enabled: Option<bool>,
    pub totp_secret: Option<String>,
}