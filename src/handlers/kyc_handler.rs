use tonic::{Request, Response, Status};
use sqlx::{PgPool, types::chrono::NaiveDate};
use uuid::Uuid;
use kyc::kyc_service_server::{KycService, KycServiceServer};
use kyc::{KycRequest, KycResponse, KycStatusRequest, KycStatusResponse};
use crate::utils::kyc::upload_document;

pub mod kyc {
    tonic::include_proto!("kyc");
}

/// **Function to create a new KYC gRPC service**
pub fn get_kyc_service(db: PgPool) -> KycServiceServer<KycServiceImpl> {
    KycServiceServer::new(KycServiceImpl { db })
}

/// **KYC Service Implementation**
pub struct KycServiceImpl {
    pub db: PgPool,
}

#[tonic::async_trait]
impl KycService for KycServiceImpl {
    /// **Submit KYC Request**
    // async fn submit_kyc(&self, request: Request<KycRequest>) -> Result<Response<KycResponse>, Status> {
    //     let req = request.into_inner();
        
    //     // ✅ Generate a unique KYC ID
    //     let kyc_id = Uuid::new_v4();

    //     // ✅ Convert user_id to UUID
    //     let user_id = Uuid::parse_str(&req.user_id)
    //         .map_err(|_| Status::invalid_argument("Invalid user_id format"))?;

    //     // ✅ Convert dob to NaiveDate
    //     let dob = NaiveDate::parse_from_str(&req.dob, "%Y-%m-%d")
    //         .map_err(|_| Status::invalid_argument("Invalid DOB format, expected YYYY-MM-DD"))?;

    //     // ✅ Validate input fields
    //     if req.full_name.is_empty()
    //         || req.address.is_empty()
    //         || req.document_type.is_empty()
    //         || req.document_url.is_empty()
    //     {
    //         return Err(Status::invalid_argument("All fields except face_scan_url are required"));
    //     }

    //     // ✅ Upload document (Save to S3 or local storage)
    //     let document_url = upload_document(&req.document_url, &req.document_type)
    //         .await
    //         .map_err(|_| Status::internal("Failed to upload document"))?;

    //     // ✅ Insert into PostgreSQL
    //     sqlx::query!(
    //         "INSERT INTO users_kyc (id, user_id, full_name, dob, address, document_type, document_url, face_scan_url, kyc_status)
    //          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')",
    //         kyc_id,
    //         user_id,
    //         req.full_name,
    //         dob,
    //         req.address,
    //         req.document_type,
    //         document_url, // ✅ Use the uploaded document URL
    //         req.face_scan_url,
    //     )
    //     .execute(&self.db)
    //     .await
    //     .map_err(|_| Status::internal("Database error while inserting KYC data"))?;

    //     Ok(Response::new(KycResponse {
    //         message: "KYC submitted successfully. Awaiting verification.".to_string(),
    //         kyc_id: kyc_id.to_string(),
    //     }))
    // }

   async fn submit_kyc(&self, request: Request<KycRequest>) -> Result<Response<KycResponse>, Status> {
    let req = request.into_inner();

    println!("Incoming KYC request: {:?}", req);

    let kyc_id = Uuid::new_v4();
    let user_id = Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("Invalid user_id format"))?;
    let dob = NaiveDate::parse_from_str(&req.dob, "%Y-%m-%d")
        .map_err(|_| Status::invalid_argument("Invalid date format, expected YYYY-MM-DD"))?;

    // let document_url = upload_document(&req.document_url, &req.document_type)
    //     .await
    //     .map_err(|_| Status::internal("Failed to upload document"))?;

    // println!("Prepared values: kyc_id={}, user_id={}, dob={}, document_url={}", kyc_id, user_id, dob, document_url);

    let query_result = sqlx::query!(
        "INSERT INTO users_kyc (id, user_id, full_name, dob, address, document_type, document_url, face_scan_url, kyc_status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')",
        kyc_id,
        user_id,
        req.full_name,
        dob,
        req.address,
        req.document_type,
        req.document_url,
        req.face_scan_url,
    )
    .execute(&self.db)
    .await;

    match query_result {
        Ok(_) => {
            println!("✅ KYC inserted successfully");
            Ok(Response::new(KycResponse {
                message: "KYC submitted successfully. Awaiting verification.".to_string(),
                kyc_id: kyc_id.to_string(),
            }))
        }
        Err(err) => {
            println!("❌ Database error: {:?}", err);
            Err(Status::internal(format!("Database error: {:?}", err)))
        }
    }
}

    /// **Get KYC Status**
    async fn get_kyc_status(&self, request: Request<KycStatusRequest>) -> Result<Response<KycStatusResponse>, Status> {
        let req = request.into_inner();

        // ✅ Convert user_id to UUID
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id format"))?;

        // ✅ Fetch KYC status from the database
        let result = sqlx::query!(
            "SELECT kyc_status, document_url, face_scan_url, created_at, updated_at 
             FROM users_kyc WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|_| Status::internal("Database error while fetching KYC status"))?;

        if let Some(row) = result {
            Ok(Response::new(KycStatusResponse {
                status: row.kyc_status.unwrap_or_default(),
                document_url: row.document_url,
                face_scan_url: row.face_scan_url.unwrap_or_default(),
                created_at: row.created_at.map_or_else(|| "".to_string(), |dt| dt.to_string()),  // ✅ Fix
                updated_at: row.updated_at.map_or_else(|| "".to_string(), |dt| dt.to_string()),  // ✅ Fix
            }))
        } else {
            Err(Status::not_found("KYC record not found"))
        }
    }
}
