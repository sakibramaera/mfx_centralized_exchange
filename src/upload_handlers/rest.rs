use actix_multipart::Multipart;
use actix_web::{post, HttpResponse, Responder};
use futures_util::StreamExt;
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;
use tokio::fs;
use tokio::io::AsyncReadExt;

#[post("/upload")]
async fn upload_image(mut payload: Multipart) -> impl Responder {
    dotenv::dotenv().ok(); // ✅ Load environment variables

    let cloud_name = env::var("CLOUDINARY_CLOUD_NAME").expect("CLOUDINARY_CLOUD_NAME not set");
    let api_key = env::var("CLOUDINARY_API_KEY").expect("CLOUDINARY_API_KEY not set");
    let upload_preset = env::var("CLOUDINARY_UPLOAD_PRESET").unwrap_or("ml_default".to_string()); // ✅ Configurable preset

    // ✅ Create temporary file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let temp_path = temp_file.path().to_owned(); // ✅ Prevent auto-delete

    // ✅ Read file from multipart request
    while let Some(field) = payload.next().await {
        let mut field = field.expect("Failed to read field");
        while let Some(chunk) = field.next().await {
            let data = chunk.expect("Failed to read chunk");
            temp_file.write_all(&data).expect("Failed to write to temp file");
        }
    }

    // ✅ Read file contents asynchronously
    let mut file = fs::File::open(&temp_path).await.expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await.expect("Failed to read file");

    // ✅ Convert file to Part
    let part = Part::bytes(buffer)
        .file_name("upload.jpg")
        .mime_str("image/jpeg")
        .expect("Failed to create multipart part");

    // ✅ Cloudinary API URL
    let cloudinary_url = format!("https://api.cloudinary.com/v1_1/{}/image/upload", cloud_name);
    
    let client = Client::new();
    
    // ✅ Correct way to attach file
    let form = Form::new()
        .part("file", part) // ✅ Fix file upload
        .text("upload_preset", upload_preset) // ✅ Required Cloudinary preset
        .text("api_key", api_key); // ✅ API key required in Cloudinary

    let response = client
        .post(&cloudinary_url)
        .multipart(form)
        .send()
        .await
        .expect("Failed to send request");

    let response_body: Value = response.json().await.expect("Failed to parse response");

    if let Some(url) = response_body["secure_url"].as_str() {
        HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "file_url": url
        }))
    } else {
        HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": response_body.to_string() // ✅ Return Cloudinary error message
        }))
    }
}
