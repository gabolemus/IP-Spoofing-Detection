/// This file contains the strcuts used for the HTTP requests and responses.
use serde::Serialize;

/// Struct that represents the general TCP/IP packet sent by the API.
#[derive(Serialize)]
pub struct SentPacket {
    /// Source IP address.
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    /// Destination IP address.
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    /// IP version.
    #[serde(rename = "IPVersion")]
    pub ip_version: u8,
    /// Port.
    pub port: u16,
    /// Data.
    pub data: String,
    /// Whether the packet was spoofed or not.
    #[serde(rename = "isSpoofed")]
    pub is_spoofed: bool,
}

/// Struct that represents the response sent by the API regarding the packet spoofing.
#[derive(Serialize)]
pub struct SpoofingResponse {
    /// General informational message.
    pub message: String,
    /// Number of packets sent.
    #[serde(rename = "packetCount")]
    pub packet_count: i32,
    /// List of packets sent.
    #[serde(rename = "sentPackets")]
    pub sent_packets: Vec<SentPacket>,
}

/// Struct that represents the general response sent by the API.
#[derive(Serialize)]
pub struct GeneralResponse {
    /// General informational message.
    pub message: String,
    /// URL for the single request page.
    #[serde(rename = "singleRequestPage")]
    pub single_request_page: String,
    /// URL for the multiple request page.
    #[serde(rename = "multipleRequestPage")]
    pub multiple_request_page: String,
}

/// Struct that represents the error response sent by the API.
#[derive(Serialize)]
pub struct ErrorResponse {
    /// Error message.
    pub error: String,
}
