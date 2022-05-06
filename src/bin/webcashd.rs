use std::collections::HashMap;
use std::sync::Mutex;

use actix_web::{
    get, http::header::ContentType, post, web, App, HttpResponse, HttpServer, Responder, Result,
};
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};

const MAX_HEALTH_CHECK_TOKENS: usize = 100;
const MAX_MINING_OUTPUT_SUBSIDY_TOKENS: usize = 1;
const MAX_MINING_OUTPUT_TOKENS: usize = 2;
const MAX_REPLACEMENT_INPUT_TOKENS: usize = 100;
const MAX_REPLACEMENT_OUTPUT_TOKENS: usize = 100;

const SERVER_BIND_ADDRESS: &str = "127.0.0.1";
const SERVER_BIND_PORT: u16 = 8000;

const JSON_STATUS_ERROR: &str = "error";
const JSON_STATUS_SUCCESS: &str = "success";

const FAKE_DIFFICULTY_TARGET_BITS: u8 = 20;
const FAKE_EPOCH: u64 = 1;
const FAKE_MINING_AMOUNT: &str = "100000.0";
const FAKE_MINING_SUBSIDY_AMOUNT: &str = "5000.0";
const FAKE_RATIO: &str = "1.00003";

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

#[cfg(not(tarpaulin_include))]
#[must_use]
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
async fn replace(
    data: web::Data<WebcashApplicationState>,
    replace_request: web::Json<ReplaceRequest>,
) -> Result<impl Responder> {
    if !replace_request.legalese.terms {
        return Ok(json_replace_response(
            JSON_STATUS_ERROR,
            "Terms of service not accepted.",
        ));
    }

    let inputs = match webcash::parse_webcash_tokens(
        &replace_request.webcashes,
        &webcash::WebcashTokenKind::Secret,
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
        &webcash::WebcashTokenKind::Secret,
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

    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    let replacement_successful = webcash_economy.replace_tokens(&inputs, &outputs);
    if !replacement_successful {
        return Ok(json_replace_response(
            JSON_STATUS_ERROR,
            "Replacement failed.",
        ));
    }
    Ok(json_replace_response(JSON_STATUS_SUCCESS, ""))
}

#[derive(Serialize)]
struct TargetResponse {
    difficulty_target_bits: u8,
    ratio: Decimal,
    mining_amount: String,
    mining_subsidy_amount: String,
    epoch: u64,
}

#[get("/api/v1/target")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn target(_data: web::Data<WebcashApplicationState>) -> impl Responder {
    // TODO: Fill with real data.
    web::Json(TargetResponse {
        difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
        ratio: Decimal::from_str_exact(FAKE_RATIO).unwrap(),
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

#[derive(Deserialize)]
struct PreimageRequest {
    webcash: Vec<String>,
    subsidy: Vec<String>,
    nonce: u64,
    timestamp: Decimal,
    difficulty: u8,
    legalese: LegaleseRequest,
}

#[post("/api/v1/mining_report")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn mining_report(
    data: web::Data<WebcashApplicationState>,
    mining_report_request: web::Json<MiningReportRequest>,
) -> Result<impl Responder> {
    // TODO: Fill with real data.
    if !mining_report_request.legalese.terms {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Terms of service not accepted."),
            difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
        }));
    }

    let preimage_bytes = match base64::decode(&mining_report_request.preimage) {
        Ok(preimage_bytes) => preimage_bytes,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not decode preimage as base64."),
                difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
            }))
        }
    };

    let preimage_as_str = match std::str::from_utf8(&preimage_bytes) {
        Ok(preimage_as_str) => preimage_as_str,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not decode preimage bytes as UTF-8."),
                difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
            }))
        }
    };

    let preimage: PreimageRequest = match serde_json::from_str(preimage_as_str) {
        Ok(preimage) => preimage,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not deserialize preimage string."),
                difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
            }))
        }
    };

    if !preimage.legalese.terms {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Terms of service not accepted in preimage JSON."),
            difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
        }));
    }

    if preimage.difficulty != FAKE_DIFFICULTY_TARGET_BITS {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Invalid difficulty in preimage JSON."),
            difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
        }));
    }

    let webcash_tokens = match webcash::parse_webcash_tokens(
        &preimage.webcash,
        &webcash::WebcashTokenKind::Secret,
        MAX_MINING_OUTPUT_TOKENS,
    ) {
        Ok(webcash_tokens) => webcash_tokens,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not parse webcash tokens."),
                difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
            }))
        }
    };
    // TODO: Check validity of PreimageRequest. JSON: {"webcash": ["e95000:secret:<hex>", "e5000:secret:<hex>"], "subsidy": ["e5000:secret:<hex>"], "nonce": 530201, "timestamp": 1651929787.514265, "difficulty": 20, "legalese": {"terms": true}}
    let _subsidy_tokens = match webcash::parse_webcash_tokens(
        &preimage.subsidy,
        &webcash::WebcashTokenKind::Secret,
        MAX_MINING_OUTPUT_SUBSIDY_TOKENS,
    ) {
        Ok(webcash_tokens) => webcash_tokens,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not parse subsidy tokens."),
                difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
            }))
        }
    };

    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    let mining_successful = webcash_economy.create_tokens(&webcash_tokens);
    if !mining_successful {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Mining failed."),
            difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
        }));
    }
    Ok(web::Json(MiningReportResponse {
        status: String::from(JSON_STATUS_SUCCESS),
        error: String::from(""),
        difficulty_target_bits: FAKE_DIFFICULTY_TARGET_BITS,
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
#[must_use]
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
async fn health_check(
    data: web::Data<WebcashApplicationState>,
    health_check_request: web::Json<Vec<String>>,
) -> Result<impl Responder> {
    let mut webcash_tokens = webcash::parse_webcash_tokens(
        &health_check_request,
        &webcash::WebcashTokenKind::Public,
        MAX_HEALTH_CHECK_TOKENS,
    );
    if webcash_tokens.is_err() {
        // Special case to allow compatibility with Python client which in some
        // parts of the client code sends secret instead of public tokens.
        webcash_tokens = webcash::parse_webcash_tokens(
            &health_check_request,
            &webcash::WebcashTokenKind::Secret,
            MAX_HEALTH_CHECK_TOKENS,
        );
    }

    let webcash_tokens = match webcash_tokens {
        Ok(webcash_tokens) => webcash_tokens,
        Err(_) => {
            return Ok(json_health_check_response(
                JSON_STATUS_ERROR,
                "Invalid token(s).",
                HashMap::<String, HealthCheckSpentResponse>::default(),
            ))
        }
    };
    assert!(!webcash_tokens.is_empty());
    assert!(webcash_tokens.len() == health_check_request.len());

    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    let mut results = HashMap::<String, HealthCheckSpentResponse>::default();
    for webcash_token in &webcash_tokens {
        let public_webcash_token = if webcash_token.token_kind == webcash::WebcashTokenKind::Public
        {
            webcash_token.clone()
        } else {
            webcash_token.to_public()
        };
        let mut spent: Option<bool> = None;
        let mut amount: Option<String> = None;
        if let Some(amount_state) = webcash_economy.get_using_public_token(&public_webcash_token) {
            spent = Some(amount_state.spent);
            amount = Some(amount_state.amount.to_string());
        }
        results.insert(
            public_webcash_token.to_string(), // TODO: Correct key even if bogus/non-matching (if amount does not match)?
            HealthCheckSpentResponse { spent, amount },
        );
    }
    assert!(results.len() == health_check_request.len());

    Ok(json_health_check_response(JSON_STATUS_SUCCESS, "", results))
}

struct WebcashApplicationState {
    webcash_economy: Mutex<webcash::WebcashEconomy>,
}

#[actix_web::main]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn main() -> std::io::Result<()> {
    println!("Starting server instance at http://{SERVER_BIND_ADDRESS}:{SERVER_BIND_PORT}/");

    let persist_to_disk = true;
    let webcash_economy = webcash::WebcashEconomy::new(persist_to_disk);
    println!(
        "The economy contains {} unspent webcash at startup.",
        webcash_economy.get_total_unspent()
    );
    let webcash_application_state = web::Data::new(WebcashApplicationState {
        webcash_economy: Mutex::new(webcash_economy),
    });

    println!("Quit the server with CONTROL-C.");

    HttpServer::new(move || {
        App::new()
            .app_data(webcash_application_state.clone())
            .service(index)
            .service(terms_html)
            .service(terms_text)
            .service(replace)
            .service(target)
            .service(mining_report)
            .service(health_check)
    })
    .bind((SERVER_BIND_ADDRESS, SERVER_BIND_PORT))?
    .run()
    .await
}

// End of File
