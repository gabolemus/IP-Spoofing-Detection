use actix_web::{App, HttpServer};
use ip_traffic_generator::{index, multiple_requests, single_request, IP_ADDRESS, PORT};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server at http://{}:{}", IP_ADDRESS, PORT);

    // Todo: create a thread to generate simulated genuine packets

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(single_request)
            .service(multiple_requests)
    })
    .bind(format!("{}:{}", IP_ADDRESS, PORT))?
    .run()
    .await
}
