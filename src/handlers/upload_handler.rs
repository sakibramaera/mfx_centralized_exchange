use tonic::{Request, Response, Status};
use reqwest::multipart;
use uuid::Uuid;
use std::env;
use upload::{UploadRequest, UploadResponse};
use upload::upload_service_server::UploadServiceServer;
use crate::handlers::upload_handler::upload::upload_service_server::UploadService;

pub fn get_upload_service() -> UploadServiceServer<UploadServiceImpl> {
    UploadServiceServer::new(UploadServiceImpl)
}

mod upload {
    tonic::include_proto!("upload");
}

pub struct UploadServiceImpl;

#[tonic::async_trait]
impl UploadService for UploadServiceImpl {
    async fn upload_image(
        &self,
        request: Request<UploadRequest>,
    ) -> Result<Response<UploadResponse>, Status> {
        let req = request.into_inner();
        let image_data = req.image_base64;

        // Load Cloudinary credentials from environment variables
        let cloud_name = env::var("CLOUDINARY_CLOUD_NAME").expect("Missing CLOUDINARY_CLOUD_NAME");
        let api_key = env::var("CLOUDINARY_API_KEY").expect("Missing CLOUDINARY_API_KEY");
        let api_secret = env::var("CLOUDINARY_API_SECRET").expect("Missing CLOUDINARY_API_SECRET");

        let cloudinary_url = format!(
            "https://api.cloudinary.com/v1_1/{}/image/upload",
            cloud_name
        );

        // Generate unique filename
        let file_name = format!("{}.jpg", Uuid::new_v4());

        // Prepare multipart form data
        let form = multipart::Form::new()
            .text("upload_preset", "ml_default")  // Adjust based on Cloudinary settings
            .text("public_id", file_name.clone())
            .text("api_key", api_key)
            .text("timestamp", format!("{}", chrono::Utc::now().timestamp()))
            .text("signature", format!("{}", api_secret)) // Use signed uploads if required
            .text("file", image_data);

        // Upload image
        let client = reqwest::Client::new();
        let response = client.post(&cloudinary_url)
            .multipart(form)
            .send()
            .await
            .map_err(|_| Status::internal("Failed to upload image"))?;

        let json_response: serde_json::Value = response.json().await.map_err(|_| Status::internal("Failed to parse response"))?;
        let url = json_response["secure_url"].as_str().unwrap_or("").to_string();

        Ok(Response::new(UploadResponse {
            url,
            message: "Image uploaded successfully".to_string(),
        }))
    }
}
