// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use actix_web::{get, http::header::ContentType, post, App, HttpResponse, HttpServer, Responder};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[get("/terms")]
async fn terms_html() -> impl Responder {
    // FIXME: This won't build on windows.
    // We should use OS-dependent path separators.
    let terms = include_str!("../terms/terms.html");
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(terms)
}

#[get("/terms/text")]
async fn terms_text() -> impl Responder {
    let terms = include_str!("../terms/terms.text");
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(terms)
}

#[post("/api/v1/replace")]
async fn replace() -> impl Responder {
    HttpResponse::Ok().body("replace")
}

#[get("/api/v1/target")]
async fn target() -> impl Responder {
    HttpResponse::Ok().body("target")
}

#[post("/api/v1/mining_report")]
async fn mining_report() -> impl Responder {
    HttpResponse::Ok().body("mining_report")
}

#[post("/api/v1/health_check")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("health_check")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server instance at http://127.0.0.1:8000/");
    println!("Quit the server with CONTROL-C.");
    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(terms_html)
            .service(terms_text)
            .service(replace)
            .service(target)
            .service(mining_report)
            .service(health_check)
    })
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
}

// End of File
