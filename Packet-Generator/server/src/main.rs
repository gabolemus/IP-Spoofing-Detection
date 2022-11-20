use actix_web::{get, http::header::ContentType, App, HttpResponse, HttpServer, Responder};
use serde::Serialize;

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

#[get("/single")]
async fn single_request() -> impl Responder {
    println!("Single request page requested");

    let response = GeneralResponse {
        message: "Welcome to the single request page!".to_string(),
        single_request_page: format!("http://{}:{}/single", IP_ADDRESS, PORT),
        multiple_request_page: format!("http://{}:{}/multiple", IP_ADDRESS, PORT),
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

#[get("/multiple")]
async fn multiple_request() -> impl Responder {
    println!("Multiple request page requested");

    let response = GeneralResponse {
        message: "Welcome to the multiple request page!".to_string(),
        single_request_page: format!("http://{}:{}/single", IP_ADDRESS, PORT),
        multiple_request_page: format!("http://{}:{}/multiple", IP_ADDRESS, PORT),
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
