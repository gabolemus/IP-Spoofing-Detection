use actix_web::{App, HttpServer};
use ip_traffic_generator::{
    api::{multiple_legitimate_requests, single_legitimate_request},
    index, multiple_requests, single_request, API_IP_ADDRESS, PORT,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!(
        "Iniciando el servidor en http://{}:{}",
        API_IP_ADDRESS, PORT
    );

    // Todo: create a thread to generate simulated legitimate packets
    // Todo: refactor API routes code

    HttpServer::new(|| {
        App::new()
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
