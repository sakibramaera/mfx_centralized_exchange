#[allow(unused_imports)]
use actix_web::{App, HttpServer};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;
use tonic::transport::Server;
mod handlers;
mod models;
mod utils; // ✅ Ensure `auth` module is included

use crate::handlers::user_handler::get_user_service;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    println!("✅ Connected to PostgreSQL");

    let addr = "[::1]:50051".parse()?;
    println!("🚀 gRPC Server running at {}", addr);

    let user_service = get_user_service(pool, jwt_secret);

    Server::builder()
        .add_service(user_service)
        .serve(addr)
        .await?;

    Ok(())
}
