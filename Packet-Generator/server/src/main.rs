use actix_cors::Cors;
use actix_web::{App, HttpServer};
use ip_traffic_generator::api::{multiple_legitimate_requests, single_legitimate_request};
use ip_traffic_generator::{index, multiple_requests, single_request, API_IP_ADDRESS, PORT};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!(
        "Iniciando el servidor en http://{}:{}",
        API_IP_ADDRESS, PORT
    );

    // Todo:
    // - Create a thread to generate simulated legitimate packets
    // - Refactor API routes code
    // - Send a GET request to http://localhost:${RANDOM_PORT} on each
    //   legitimate request to simulate a real user

    HttpServer::new(|| {
        // Set CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .service(index)
            .service(single_request)
            .service(multiple_requests)
            .service(single_legitimate_request)
            .service(multiple_legitimate_requests)
    })
    .bind(format!("{}:{}", API_IP_ADDRESS, PORT))?
    .run()
    .await
}
