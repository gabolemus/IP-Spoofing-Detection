/// This file contains the routes for the API.
use crate::api::{ErrorResponse, GeneralResponse, GenericResponse, SpoofingResponse};
use crate::model::ip_to_string;
use crate::model::networking::{get_local_ip, socket::SocketError};
use crate::model::utils::legitimate_packets::send_multiple_legitimate_packets;
use crate::model::utils::{send_multiple_packets, send_single_legitimate_packet};
use crate::model::utils::{MultipleRequestParams, SingleRequestParams};
use crate::send_single_packet;
use actix_web::{get, http::header::ContentType, post, web, HttpResponse, Responder};

// Declare the ip address and port globally
pub const API_IP_ADDRESS: &str = "0.0.0.0";
pub const DESTINATION_IP_ADDRESS: &str = "8.8.8.8";
pub const PORT: &str = "8080";
pub const DUMMY_MESSAGE: &str = "Este es un paquete spoofeado";
pub static mut STOP_INFINITE_PACKETS: bool = false;
pub static mut SENDING_INFINITE_PACKETS: bool = false;
pub static mut THREAD_COUNT: u32 = 0;

/// Route that shows the index page.
#[get("/")]
pub async fn index() -> impl Responder {
    println!("Página principal solicitada");

    // Show a welcome message and return the links to the single and multiple request pages.
    let response = GeneralResponse {
        message: "¡Bienvenido a la API de spoofing de paquetes!".to_string(),
        single_spoofed_request_page: format!("http://{}:{}/single-spoofed", API_IP_ADDRESS, PORT),
        multiple_spoofed_request_page: format!(
            "http://{}:{}/multiple-spoofed",
            API_IP_ADDRESS, PORT
        ),
        single_legitimate_request_page: format!(
            "http://{}:{}/single-legitimate",
            API_IP_ADDRESS, PORT
        ),
        multiple_legitimate_request_page: format!(
            "http://{}:{}/multiple-legitimate",
            API_IP_ADDRESS, PORT
        ),
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

/// Route that generates a single spoofed packet.
#[post("/single-spoofed")]
// Get the body parameters and send a single spoofed or legitimate packet
pub async fn single_request(params: web::Json<SingleRequestParams>) -> impl Responder {
    unsafe {
        if !SENDING_INFINITE_PACKETS {
            let source_ip = ip_to_string(&params.source_ip, &get_local_ip("127.0.0.1"));
            let destination_ip = ip_to_string(&params.destination_ip, "8.8.8.8");
            let spoof_packet = match params.set_evil_bit {
                Some(set_evil_bit) => set_evil_bit,
                None => true,
            };

            println!(
                "Paquete único spoofeado: {} --> {}",
                source_ip, destination_ip
            );

            // Construct the response
            let response = SpoofingResponse {
                message: "Paquete único enviado.".to_string(),
                packet_count: 1,
            };

            // Attempt to send the packet and handle the error if it occurs
            match send_single_packet(params, spoof_packet) {
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
                                error_msg =
                                    "La opción IP_HDRINCL para el socket no pudo ser establecida."
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
        } else {
            HttpResponse::Ok()
            .content_type(ContentType::json())
            .json(GenericResponse {
                message: format!("No es posible enviar un paquete único mientras se envían paquetes infinitos. Por favor, detenga la generación de paquetes infinitos enviando una solicitud POST a la ruta http://{}:{}/multiple-spoofed/stop si así lo desea.", API_IP_ADDRESS, PORT),
            })
        }
    }
}

/// Route that generates multiple spoofed packets.
#[post("/multiple-spoofed/{stop}")]
pub async fn multiple_requests(
    params: web::Json<MultipleRequestParams>,
    path: web::Path<String>,
) -> impl Responder {
    if path.into_inner() == "stop" {
        println!("Deteniendo el envío de paquetes...");

        unsafe {
            STOP_INFINITE_PACKETS = true;
            SENDING_INFINITE_PACKETS = false;
        }

        // Return a response
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .json(GenericResponse {
                message: "Envío de paquetes infinitos detenido.".to_string(),
            })
    } else {
        unsafe {
            if !SENDING_INFINITE_PACKETS && THREAD_COUNT < 10 {
                STOP_INFINITE_PACKETS = false;
                SENDING_INFINITE_PACKETS = match params.packet_count {
                    Some(count) => count == -1,
                    None => false,
                };

                let spoof_packet = match &params.packet_data {
                    Some(packet_data) => match packet_data.set_evil_bit {
                        Some(set_evil_bit) => set_evil_bit,
                        None => true,
                    },
                    None => true,
                };
                let randomize_source_ip = match &params.random_source_ip {
                    Some(randomize_source_ip) => *randomize_source_ip,
                    None => false,
                };

                let packet_count_msg = match params.packet_count {
                    Some(-1) => "Enviando una cantidad indefinida de paquetes...".to_string(),
                    Some(count) => format!("Enviando {} paquetes...", count),
                    None => "Enviando una cantidad indefinida de paquetes...".to_string(),
                };
                println!("Múltiples paquetes solicitados. {}", packet_count_msg);

                // Get the packet data if it's provided or create a default one
                let packet_data = params
                    .packet_data
                    .clone()
                    .unwrap_or(SingleRequestParams::get_default_packet());
                let packet_data = web::Json(packet_data);
                let packet_count = params.packet_count.unwrap_or(1);

                // Construct the response
                let response = SpoofingResponse {
                    message: "Múltiples paquetes enviados.".to_string(),
                    packet_count,
                };

                match send_multiple_packets(
                    packet_data,
                    packet_count,
                    params.wait_time,
                    spoof_packet,
                    randomize_source_ip,
                )
                .await
                {
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
                                    error_msg =
                                    "La opción IP_HDRINCL para el socket no pudo ser establecida."
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
            } else {
                HttpResponse::Ok()
                .content_type(ContentType::json())
                .json(GenericResponse {
                    message: format!("No es posible enviar múltiples paquetes mientras se están enviando paquetes actualmente. Puede detener el envío de paquetes enviando una solicitud POST a la ruta http://{}:{}/multiple/stop si así lo desea.", API_IP_ADDRESS, PORT),
                })
            }
        }
    }
}

/// Route that generates legitimate packets.
#[post("/single-legitimate")]
pub async fn single_legitimate_request() -> impl Responder {
    let dest_ip = String::new();

    match send_single_legitimate_packet(&dest_ip, false, None, 0) {
        Ok(_) => HttpResponse::Ok()
            .content_type(ContentType::json())
            .json(GenericResponse {
                message: "Un paquete legítimo ha sido enviado.".to_string(),
            }),
        Err(err) => HttpResponse::InternalServerError()
            .content_type(ContentType::json())
            .json(ErrorResponse {
                error: format!("Error al enviar el paquete legítimo: {}", err),
            }),
    }
}

/// Route that generates multiple legitimate packets.
#[post("/multiple-legitimate/{stop}")]
pub async fn multiple_legitimate_requests(
    path: web::Path<String>,
    params: web::Json<MultipleRequestParams>,
) -> impl Responder {
    if path.into_inner() == "stop" {
        println!("Deteniendo el envío de paquetes...");

        unsafe {
            STOP_INFINITE_PACKETS = true;
            SENDING_INFINITE_PACKETS = false;
        }

        // Return a response
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .json(GenericResponse {
                message: "Envío de paquetes infinitos detenido.".to_string(),
            })
    } else {
        unsafe {
            if !SENDING_INFINITE_PACKETS && THREAD_COUNT < 10 {
                STOP_INFINITE_PACKETS = false;
                SENDING_INFINITE_PACKETS = match params.packet_count {
                    Some(count) => count == -1,
                    None => false,
                };

                let randomize_source_ip = match &params.random_source_ip {
                    Some(randomize_source_ip) => *randomize_source_ip,
                    None => false,
                };

                let packet_count_msg = match params.packet_count {
                    Some(-1) => "Enviando una cantidad indefinida de paquetes...".to_string(),
                    Some(count) => format!("Enviando {} paquetes...", count),
                    None => "Enviando una cantidad indefinida de paquetes...".to_string(),
                };
                let packet_count = params.packet_count.unwrap_or(1);
                println!("Múltiples paquetes solicitados. {}", packet_count_msg);

                // Construct the response
                let response = SpoofingResponse {
                    message: "Múltiples paquetes enviados.".to_string(),
                    packet_count,
                };

                // match send_multiple_legitimate_packets(destination_ip, randomize_source_ip, number_of_packets)
                match send_multiple_legitimate_packets(
                    String::new(),
                    randomize_source_ip,
                    packet_count,
                ) {
                    Ok(_) => HttpResponse::Ok()
                        .content_type(ContentType::json())
                        .json(response),
                    Err(err) => HttpResponse::InternalServerError()
                        .content_type(ContentType::json())
                        .json(ErrorResponse {
                            error: format!("Error al enviar los paquetes legítimos: {}", err),
                        }),
                }
            } else {
                HttpResponse::Ok()
                .content_type(ContentType::json())
                .json(GenericResponse {
                    message: format!("No es posible enviar múltiples paquetes mientras se están enviando paquetes actualmente. Puede detener el envío de paquetes enviando una solicitud POST a la ruta http://{}:{}/multiple-legitimate/stop si así lo desea.", API_IP_ADDRESS, PORT),
                })
            }
        }
    }
}
