/// This file contains the routes for the API.
use crate::{
    api::{ErrorResponse, GeneralResponse, SentPacket, SpoofingResponse},
    model::{
        ip_to_string,
        networking::socket::SocketError,
        utils::{
            send_multiple_packets, stop_sending_packets, MultipleRequestParams, SingleRequestParams,
        },
    },
    send_single_packet,
};
use actix_web::{get, http::header::ContentType, post, web, HttpResponse, Responder};

// Declare the ip address and port globally
pub const SOURCE_IP_ADDRESS: &str = "0.0.0.0";
pub const DESTINATION_IP_ADDRESS: &str = "8.8.8.8";
pub const PORT: &str = "8080";
pub const DUMMY_MESSAGE: &str = "Este es un paquete spoofeado!";

/// Route that shows the index page.
#[get("/")]
pub async fn index() -> impl Responder {
    println!("Index page requested");

    // Show a welcome message and return the links to the single and multiple request pages.
    let response = GeneralResponse {
        message: "Welcome to the TCP/IP packet spoofing API!".to_string(),
        single_request_page: format!("http://{}:{}/single", SOURCE_IP_ADDRESS, PORT),
        multiple_request_page: format!("http://{}:{}/multiple", SOURCE_IP_ADDRESS, PORT),
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
    // // Mutex
    // let pair = Arc::new((Mutex::new(false), Condvar::new()));
    // let pair2 = pair.clone();
    // let &(ref lock, ref cvar) = &*pair2;
    // let mut stop_infinite_loop = lock.lock().unwrap();

    let packet_count_str = match params.packet_count {
        Some(-1) => "indefinite".to_string(),
        Some(count) => count.to_string(),
        None => "indefinite".to_string(),
    };
    println!(
        "Multiple request page. Serving {} packets.",
        packet_count_str
    );

    // Get the packet data if it's provided or create a default one
    let packet_data = params
        .packet_data
        .clone()
        .unwrap_or(SingleRequestParams::get_default_packet());
    let packet_data = web::Json(packet_data);
    let packet_count = params.packet_count.unwrap_or(-1);

    // Construct the response
    let response = SpoofingResponse {
        message: "Multiple request page".to_string(),
        packet_count,
        sent_packets: vec![],
    };

    match send_multiple_packets(packet_data, packet_count).await {
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

/// Route to stop sending the infinite packets.
#[post("/stop")]
pub async fn stop() -> impl Responder {
    println!("Stop page requested");

    // Construct the response
    let response = GeneralResponse {
        message: "Stop page".to_string(),
        single_request_page: format!("http://{}:{}/single", SOURCE_IP_ADDRESS, PORT),
        multiple_request_page: format!("http://{}:{}/multiple", SOURCE_IP_ADDRESS, PORT),
    };

    // Stop the infinite packet sending
    stop_sending_packets();

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}
