use actix_web::{get, http::header::ContentType, web, App, HttpResponse, HttpServer, Responder};
use serde::Serialize;

#[derive(Serialize)]
struct TestResponse {
    msg: String,
}

#[get("/")]
async fn index() -> impl Responder {
    println!("Server says: Hello World!");

    let response = TestResponse {
        msg: "Hello World!".to_string(),
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    println!("Server says: Hello {}!", name);

    let response = TestResponse {
        msg: format!("Hello {}!", name),
    };

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let (ip_address, port) = ("127.0.0.1", "8080");
    println!("Starting server at http://{}:{}", ip_address, port);

    HttpServer::new(|| App::new().service(index).service(greet))
        .bind(format!("{}:{}", ip_address, port))?
        .run()
        .await
}
