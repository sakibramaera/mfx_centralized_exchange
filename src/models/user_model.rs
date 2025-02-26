use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(sqlx::FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: Option<String>,
    pub password: String,
    pub mobile_number: Option<String>,
    pub role: Option<String>,
    pub is_verified: Option<bool>,
}