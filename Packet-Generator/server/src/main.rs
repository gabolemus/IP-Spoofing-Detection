use actix_web::{App, HttpServer};
use ip_traffic_generator::{index, multiple_requests, single_request, PORT, SOURCE_IP_ADDRESS};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Iniciando el servidor en http://{}:{}", SOURCE_IP_ADDRESS, PORT);

    // Todo: create a thread to generate simulated genuine packets
    // Todo: refactor API routes code

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(single_request)
            .service(multiple_requests)
    })
    .bind(format!("{}:{}", SOURCE_IP_ADDRESS, PORT))?
    .run()
    .await
}
