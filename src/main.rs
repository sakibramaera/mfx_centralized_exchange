#[allow(unused_imports)]
use actix_web::{App, HttpServer};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;
use tonic::transport::Server;
use tokio::task;

mod handlers;
mod models;
mod utils;
mod upload_handlers;

use crate::handlers::auth_handler::get_auth_service;
use crate::handlers::kyc_handler::get_kyc_service; // ✅ Ensure KYC service is included
use crate::handlers::upload_handler::get_upload_service; // ✅ Add upload service
use crate::upload_handlers::rest::upload_image; // ✅ Import REST Upload

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

    let rest_addr = "127.0.0.1:8080";
    println!("🌍 REST Server running at http://{}", rest_addr);

    let auth_service = get_auth_service(pool.clone(), jwt_secret.clone());
    let kyc_service = get_kyc_service(pool.clone()); // ✅ Initialize KYC service
    let upload_service = get_upload_service(); // ✅ Initialize Upload Service

  let grpc_task = task::spawn(async move {
        Server::builder()
            .add_service(auth_service)
            .add_service(kyc_service) // ✅ Add KYC gRPC service
            .add_service(upload_service) // ✅ Register Upload Service
            .serve(addr)
            .await
            .unwrap();
    });

    // REST Server Task
    let rest_task = task::spawn(async move {
        HttpServer::new(move || {
            App::new()
                .service(upload_image) // ✅ REST Upload API
        })
        .bind(rest_addr)
        .unwrap()
        .run()
        .await
        .unwrap();
    });

    // Run both gRPC and REST in parallel
    tokio::try_join!(grpc_task, rest_task)?;

    Ok(())
}
