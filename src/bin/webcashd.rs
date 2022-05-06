use std::collections::HashMap;

use actix_web::{
    get, http::header::ContentType, post, web, App, HttpResponse, HttpServer, Responder, Result,
};
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};

const MAX_HEALTH_CHECK_TOKENS: usize = 100;
const MAX_REPLACEMENT_INPUT_TOKENS: usize = 100;
const MAX_REPLACEMENT_OUTPUT_TOKENS: usize = 100;

#[get("/")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("webcashd\n")
}

#[get("/terms")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn terms_html() -> impl Responder {
    // FIXME: This won't build on windows.
    // We should use OS-dependent path separators.
    let terms = include_str!("../../terms/terms.html");
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(terms)
}

#[get("/terms/text")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn terms_text() -> impl Responder {
    let terms = include_str!("../../terms/terms.text");
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(terms)
}

#[derive(Deserialize)]
struct LegaleseRequest {
    terms: bool,
}

#[derive(Deserialize)]
struct ReplaceRequest {
    legalese: LegaleseRequest,
    webcashes: Vec<String>,
    new_webcashes: Vec<String>,
}

#[derive(Serialize)]
struct ReplaceResponse {
    status: String,
    error: String,
}

const JSON_STATUS_SUCCESS: &str = "success";
const JSON_STATUS_ERROR: &str = "error";

#[cfg(not(tarpaulin_include))]
fn json_replace_response(status_message: &str, error_message: &str) -> impl actix_web::Responder {
    assert!(status_message == JSON_STATUS_SUCCESS || status_message == JSON_STATUS_ERROR);
    web::Json(ReplaceResponse {
        status: status_message.to_string(),
        error: error_message.to_string(),
    })
}

#[post("/api/v1/replace")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn replace(replace_request: web::Json<ReplaceRequest>) -> Result<impl Responder> {
    if !replace_request.legalese.terms {
        return Ok(json_replace_response(
            JSON_STATUS_ERROR,
            "Terms of service not accepted.",
        ));
    }

    let inputs = match webcash::parse_webcash_tokens(
        &replace_request.webcashes,
        false,
        MAX_REPLACEMENT_INPUT_TOKENS,
    ) {
        Ok(inputs) => inputs,
        Err(_) => {
            return Ok(json_replace_response(
                JSON_STATUS_ERROR,
                "Invalid input(s).",
            ))
        }
    };
    assert_eq!(inputs.len(), replace_request.webcashes.len());
    assert!(inputs
        .iter()
        .all(|wc| wc.token_kind == webcash::WebcashTokenKind::Secret));

    let outputs = match webcash::parse_webcash_tokens(
        &replace_request.new_webcashes,
        false,
        MAX_REPLACEMENT_OUTPUT_TOKENS,
    ) {
        Ok(outputs) => outputs,
        Err(_) => {
            return Ok(json_replace_response(
                JSON_STATUS_ERROR,
                "Invalid output(s).",
            ))
        }
    };
    assert_eq!(outputs.len(), replace_request.new_webcashes.len());
    assert!(outputs
        .iter()
        .all(|wc| wc.token_kind == webcash::WebcashTokenKind::Secret));

    let total_input: Decimal = inputs.iter().map(|wc| wc.amount).sum();
    let total_output: Decimal = outputs.iter().map(|wc| wc.amount).sum();
    if total_input != total_output {
        return Ok(json_replace_response(JSON_STATUS_ERROR, "Amount mismatch."));
    }

    // TODO: Atomic data store verification and replacement of tokens.

    Ok(json_replace_response(JSON_STATUS_SUCCESS, ""))
}

const FAKE_DIFFICULTY_TARGET_BITS: u8 = 20;
const FAKE_RATIO: f64 = 1.00003;
const FAKE_MINING_AMOUNT: &str = "100000.0";
const FAKE_MINING_SUBSIDY_AMOUNT: &str = "5000.0";
const FAKE_EPOCH: u64 = 1;

#[derive(Serialize)]
struct TargetResponse {
    difficulty_target_bits: u8,
    ratio: f64,
    mining_amount: String,
    mining_subsidy_amount: String,
    epoch: u64,
}

#[get("/api/v1/target")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn target() -> impl Responder {
    // TODO: Fill with real data.
    web::Json(TargetResponse {
        difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
        ratio: FAKE_RATIO,
        mining_amount: String::from(FAKE_MINING_AMOUNT),
        mining_subsidy_amount: String::from(FAKE_MINING_SUBSIDY_AMOUNT),
        epoch: FAKE_EPOCH,
    })
}

#[derive(Deserialize)]
struct MiningReportRequest {
    work: u128, // TODO: Use u256 here.
    preimage: String,
    legalese: LegaleseRequest,
}

#[derive(Serialize)]
struct MiningReportResponse {
    status: String,
    error: String,
    difficulty_target_bits: u8,
}

#[post("/api/v1/mining_report")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn mining_report(
    mining_report_request: web::Json<MiningReportRequest>,
) -> Result<impl Responder> {
    // TODO: Fill with real data.
    let difficulty_target_bits = FAKE_DIFFICULTY_TARGET_BITS;

    if !mining_report_request.legalese.terms {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Terms of service not accepted."),
            difficulty_target_bits,
        }));
    }

    // TODO: Fill with real data.
    Ok(web::Json(MiningReportResponse {
        status: String::from(JSON_STATUS_SUCCESS),
        error: String::from(""),
        difficulty_target_bits,
    }))
}

#[derive(Serialize)]
struct HealthCheckSpentResponse {
    spent: Option<bool>,
    amount: Option<String>,
}

#[derive(Serialize)]
struct HealthCheckResponse {
    status: String,
    error: String,
    results: HashMap<String, HealthCheckSpentResponse>,
}

#[cfg(not(tarpaulin_include))]
fn json_health_check_response(
    status_message: &str,
    error_message: &str,
    results: HashMap<String, HealthCheckSpentResponse>,
) -> impl actix_web::Responder {
    assert!(status_message == JSON_STATUS_SUCCESS || status_message == JSON_STATUS_ERROR);
    web::Json(HealthCheckResponse {
        status: status_message.to_string(),
        error: error_message.to_string(),
        results,
    })
}

#[post("/api/v1/health_check")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn health_check(health_check_request: web::Json<Vec<String>>) -> Result<impl Responder> {
    // TODO: Public or private webcash expected here?
    let webcash_tokens =
        match webcash::parse_webcash_tokens(&health_check_request, true, MAX_HEALTH_CHECK_TOKENS) {
            Ok(webcash_tokens) => webcash_tokens,
            Err(_) => {
                return Ok(json_health_check_response(
                    JSON_STATUS_ERROR,
                    "Invalid token(s).",
                    HashMap::<String, HealthCheckSpentResponse>::new(),
                ))
            }
        };
    assert!(!webcash_tokens.is_empty());
    assert!(webcash_tokens.len() == health_check_request.len());

    let mut results = HashMap::<String, HealthCheckSpentResponse>::new();
    // TODO: Fill response with correct data.
    for webcash_token in &webcash_tokens {
        let spent = Some(false); // TODO: Check data store status.
        let public_webcash_token = if webcash_token.token_kind == webcash::WebcashTokenKind::Public
        {
            webcash_token.clone()
        } else {
            webcash_token.to_public()
        };
        results.insert(
            public_webcash_token.to_string(),
            HealthCheckSpentResponse {
                spent,
                amount: Some(public_webcash_token.amount.to_string()),
            },
        );
    }
    assert!(results.len() == health_check_request.len());

    Ok(json_health_check_response(JSON_STATUS_SUCCESS, "", results))
}

const SERVER_HOSTNAME: &str = "127.0.0.1";
const SERVER_PORT: u16 = 8000;

#[actix_web::main]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn main() -> std::io::Result<()> {
    println!("Starting server instance at http://{SERVER_HOSTNAME}:{SERVER_PORT}/");
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
    .bind((SERVER_HOSTNAME, SERVER_PORT))?
    .run()
    .await
}

// End of File
