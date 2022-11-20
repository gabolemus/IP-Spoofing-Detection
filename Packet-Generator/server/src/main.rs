use actix_web::{
    get, http::header::ContentType, post, web, App, HttpResponse, HttpServer, Responder,
};
use serde::{Deserialize, Serialize};

// Declare the ip address and port globally
const IP_ADDRESS: &str = "127.0.0.1";
const PORT: &str = "8080";

#[derive(Serialize)]
struct SentPacket {
    #[serde(rename = "sourceIP")]
    source_ip: String,
    #[serde(rename = "destinationIP")]
    destination_ip: String,
    #[serde(rename = "IPVersion")]
    ip_version: u8,
    port: u16,
    data: String,
    #[serde(rename = "isSpoofed")]
    is_spoofed: bool,
}

#[derive(Serialize)]
struct SpoofingResponse {
    message: String,
    #[serde(rename = "packetCount")]
    packet_count: u32,
    #[serde(rename = "sentPackets")]
    sent_packets: Vec<SentPacket>,
}

#[derive(Serialize)]
struct GeneralResponse {
    message: String,
    #[serde(rename = "singleRequestPage")]
    single_request_page: String,
    #[serde(rename = "multipleRequestPage")]
    multiple_request_page: String,
}

#[derive(Serialize, Debug, Deserialize)]
struct SingleRequestParams {
    #[serde(rename = "isSpoofed")]
    is_spoofed: bool,
    #[serde(rename = "sourceIP")]
    source_ip: Option<String>,
    #[serde(rename = "destinationIP")]
    destination_ip: Option<String>,
    #[serde(rename = "IPVersion")]
    ip_version: u8,
    port: u16,
    data: String,
}

#[derive(Serialize, Debug, Deserialize)]
struct MultipleRequestParams {
    #[serde(rename = "isSpoofed")]
    is_spoofed: bool,
    #[serde(rename = "sourceIP")]
    source_ip: Option<String>,
    #[serde(rename = "destinationIP")]
    destination_ip: Option<String>,
    #[serde(rename = "IPVersion")]
    ip_version: u8,
    port: u16,
    data: String,
    // The packet count will determine the number of packets to send
    // If it's -1, then send packets until a post request is made to /stop
    #[serde(rename = "packetCount")]
    packet_count: Option<u32>,
}

#[get("/")]
async fn index() -> impl Responder {
    println!("Index page requested");

    let response = GeneralResponse {
        message: "Welcome to the TCP/IP packet spoofing API!".to_string(),
        single_request_page: format!("http://{}:{}/single", IP_ADDRESS, PORT),
        multiple_request_page: format!("http://{}:{}/multiple", IP_ADDRESS, PORT),
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

#[post("/single")]
// Get the body parameters and send a single spoofed or legitimate packet
async fn single_request(params: web::Json<SingleRequestParams>) -> impl Responder {
    println!("Single request page requested");

    let response = SpoofingResponse {
        message: "Single request page".to_string(),
        packet_count: 1,
        sent_packets: vec![SentPacket {
            source_ip: match &params.source_ip {
                Some(ip) => ip.to_string(),
                None => "127.0.0.1".to_string(),
            },
            destination_ip: match &params.destination_ip {
                Some(ip) => ip.to_string(),
                None => "8.8.8.8".to_string(),
            },
            ip_version: params.ip_version,
            port: params.port,
            data: params.data.to_string(),
            is_spoofed: params.is_spoofed,
        }],
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

#[post("/multiple")]
async fn multiple_request(params: web::Json<MultipleRequestParams>) -> impl Responder {
    println!("Multiple request page requested");

    let response = SpoofingResponse {
        message: "Multiple request page".to_string(),
        packet_count: params.packet_count.unwrap_or(1),
        sent_packets: vec![SentPacket {
            source_ip: match &params.source_ip {
                Some(ip) => ip.to_string(),
                None => "127.0.0.1".to_string(),
            },
            destination_ip: match &params.destination_ip {
                Some(ip) => ip.to_string(),
                None => "8.8.8.8".to_string(),
            },
            ip_version: params.ip_version,
            port: params.port,
            data: params.data.to_string(),
            is_spoofed: params.is_spoofed,
        }],
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server at http://{}:{}", IP_ADDRESS, PORT);

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(single_request)
            .service(multiple_request)
    })
    .bind(format!("{}:{}", IP_ADDRESS, PORT))?
    .run()
    .await
}
