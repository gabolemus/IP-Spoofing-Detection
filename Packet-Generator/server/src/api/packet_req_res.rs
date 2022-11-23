/// This file contains the strcuts used for the HTTP requests and responses.
use serde::Serialize;

/// Struct that represents the response sent by the API regarding the packet spoofing.
#[derive(Serialize)]
pub struct SpoofingResponse {
    /// General informational message.
    pub message: String,
    /// Number of packets sent.
    #[serde(rename = "packetCount")]
    pub packet_count: i32,
}

/// Struct that represents the general response sent by the API.
#[derive(Serialize)]
pub struct GeneralResponse {
    /// General informational message.
    pub message: String,
    /// URL for the single spoofed packet page.
    #[serde(rename = "singleSpoofedRequestPage")]
    pub single_spoofed_request_page: String,
    /// URL for the multiple spoofed packets page.
    #[serde(rename = "multipleSpoofedRequestPage")]
    pub multiple_spoofed_request_page: String,
    /// URL for the single legitimate packet page.
    #[serde(rename = "singleLegitimateRequestPage")]
    pub single_legitimate_request_page: String,
    /// URL for the multiple legitimate packets page.
    #[serde(rename = "multipleLegitimateRequestPage")]
    pub multiple_legitimate_request_page: String,
}

/// Generic response sent by the API to provide information.
#[derive(Serialize)]
pub struct GenericResponse {
    /// General informational message.
    pub message: String,
}

/// Struct that represents the error response sent by the API.
#[derive(Serialize)]
pub struct ErrorResponse {
    /// Error message.
    pub error: String,
}
