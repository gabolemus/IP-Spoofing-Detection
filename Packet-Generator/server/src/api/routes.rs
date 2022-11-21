/// This file contains the routes for the API.
use crate::{
    model::{
        ip_to_string,
        networking::socket::SocketError,
        utils::{MultipleRequestParams, SingleRequestParams},
    },
    send_single_packet, api::{GeneralResponse, SpoofingResponse, SentPacket, ErrorResponse},
};
use actix_web::{get, http::header::ContentType, post, web, HttpResponse, Responder};

// Declare the ip address and port globally
pub const IP_ADDRESS: &str = "0.0.0.0";
pub const PORT: &str = "8080";

/// Route that shows the index page.
#[get("/")]
pub async fn index() -> impl Responder {
    println!("Index page requested");

    // Show a welcome message and return the links to the single and multiple request pages.
    let response = GeneralResponse {
        message: "Welcome to the TCP/IP packet spoofing API!".to_string(),
        single_request_page: format!("http://{}:{}/single", IP_ADDRESS, PORT),
        multiple_request_page: format!("http://{}:{}/multiple", IP_ADDRESS, PORT),
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

/// Route that generates a single spoofed or genuine packet.
#[post("/single")]
// Get the body parameters and send a single spoofed or legitimate packet
pub async fn single_request(params: web::Json<SingleRequestParams>) -> impl Responder {
    let source_ip = ip_to_string(&params.source_ip, "127.0.0.1");
    let destination_ip = ip_to_string(&params.destination_ip, "8.8.8.8");

    println!("Packet {} --> {}", source_ip, destination_ip);

    // Construct the response
    let response = SpoofingResponse {
        message: "Single request page".to_string(),
        packet_count: 1,
        sent_packets: vec![SentPacket {
            source_ip,
            destination_ip,
            ip_version: params.ip_version.unwrap_or(4),
            port: params.port.unwrap_or(80),
            data: params
                .data
                .clone()
                .unwrap_or("Paquete spoofeado!".to_string()),
            is_spoofed: params.is_spoofed.unwrap_or(false),
        }],
    };

    // Attempt to send the packet and handle the error if it occurs
    match send_single_packet(params) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::json())
            .json(response),
        Err(err) => {
            let error_msg;

            if err.is::<SocketError>() {
                match err.downcast_ref::<SocketError>().unwrap() {
                    SocketError::SocketCreationError => {
                        error_msg = "El socket no pudo ser creado. Por favor, asegúrese de ejecutar este programa con privilegios de administrador.".to_string();
                    }

                    SocketError::SetHeaderError => {
                        error_msg = "La opción IP_HDRINCL para el socket no pudo ser establecida."
                            .to_string();
                    }
                }
            } else {
                error_msg = format!("{}", err);
            }

            HttpResponse::InternalServerError()
                .content_type(ContentType::json())
                .json(ErrorResponse {
                    error: format!("{}", error_msg),
                })
        }
    }
}

/// Route that generates multiple spoofed or genuine packets.
#[post("/multiple")]
pub async fn multiple_requests(params: web::Json<MultipleRequestParams>) -> impl Responder {
    println!("Multiple request page requested");

    // Construct the response
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
            ip_version: params.ip_version.unwrap_or(4),
            port: params.port.unwrap_or(80),
            data: params
                .data
                .clone()
                .unwrap_or("Paquete spoofeado!".to_string()),
            is_spoofed: params.is_spoofed.unwrap_or(false),
        }],
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}
