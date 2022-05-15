use std::collections::HashMap;
use std::sync::Mutex;

use actix_web::{
    get, http::header::ContentType, post, web, App, HttpResponse, HttpServer, Responder, Result,
};
use thousands::Separable;
#[macro_use]
extern crate log;
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};

const DEFAULT_RUST_LOG: &str = "info,actix_server=warn";

const SERVER_BIND_ADDRESS: &str = "127.0.0.1";
const SERVER_BIND_PORT: u16 = 8000;

const JSON_STATUS_ERROR: &str = "error";
const JSON_STATUS_SUCCESS: &str = "success";

#[get("/")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("webcashd\n")
}

#[cfg(host_family = "windows")]
macro_rules! PATH_SEPARATOR {
    () => {
        r"\"
    };
}

#[cfg(not(host_family = "windows"))]
macro_rules! PATH_SEPARATOR {
    () => {
        r"/"
    };
}

#[get("/terms")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn terms_html() -> impl Responder {
    let terms = include_str!(concat!(
        "..",
        PATH_SEPARATOR!(),
        "..",
        PATH_SEPARATOR!(),
        "terms",
        PATH_SEPARATOR!(),
        "terms.html"
    ));
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(terms)
}

#[get("/terms/text")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn terms_text() -> impl Responder {
    let terms = include_str!(concat!(
        "..",
        PATH_SEPARATOR!(),
        "..",
        PATH_SEPARATOR!(),
        "terms",
        PATH_SEPARATOR!(),
        "terms.text"
    ));
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
    #[serde(skip_serializing_if = "String::is_empty")]
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

const MAX_REPLACEMENT_INPUT_TOKENS: usize = 100;
const MAX_REPLACEMENT_OUTPUT_TOKENS: usize = 100;

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
    epoch: u32,
}

#[get("/api/v1/target")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn target(data: web::Data<WebcashApplicationState>) -> impl Responder {
    // TODO: Fill with real data.
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    web::Json(TargetResponse {
        difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        ratio: webcash_economy.get_ratio(),
        mining_amount: webcash::mining_amount_for_mining_report(
            webcash_economy.get_mining_reports(),
        )
        .to_string(),
        mining_subsidy_amount: webcash::mining_subsidy_amount_for_mining_report(
            webcash_economy.get_mining_reports(),
        )
        .to_string(),
        epoch: webcash::epoch(webcash_economy.get_mining_reports()),
    })
}

#[derive(Serialize)]
struct StatsResponse {
    circulation_formatted: String, // NOTE: Inexact. Live environment does not use decimals here. Uses integers?
    circulation: u64, // NOTE: Inexact. Live environment does not use decimals here. Uses integers?
    difficulty_target_bits: u8,
    ratio: f64,            // TODO/FIX: float here but string (decimal) in target API call.
    mining_amount: String, // NOTE: Live environment has "mining_amount": "50000.0", "mining_subsidy_amount": "2500.00". Different granularity?
    mining_subsidy_amount: String, // NOTE: Live environment has "mining_amount": "50000.0", "mining_subsidy_amount": "2500.00". Different granularity?
    epoch: u32,
    mining_reports: u32,
}

#[get("/stats")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn stats(data: web::Data<WebcashApplicationState>) -> impl Responder {
    // TODO: Fill with real data.
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    web::Json(StatsResponse {
        circulation_formatted: webcash::total_circulation(webcash_economy.get_mining_reports())
            .trunc()
            .to_u64()
            .unwrap()
            .separate_with_commas(), // NOTE: Not exact.
        circulation: webcash::total_circulation(webcash_economy.get_mining_reports())
            .trunc()
            .to_u64()
            .unwrap(), // NOTE: Not exact.
        difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        ratio: webcash_economy.get_ratio().to_f64().unwrap(),
        mining_amount: webcash::mining_amount_for_mining_report(
            webcash_economy.get_mining_reports(),
        )
        .to_string(),
        mining_subsidy_amount: webcash::mining_subsidy_amount_for_mining_report(
            webcash_economy.get_mining_reports(),
        )
        .to_string(),
        epoch: webcash::epoch(webcash_economy.get_mining_reports()),
        mining_reports: webcash_economy.get_mining_reports(),
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
    #[serde(skip_serializing_if = "String::is_empty")]
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

const MAX_MINING_OUTPUT_SUBSIDY_TOKENS: usize = 100;
const MAX_MINING_OUTPUT_TOKENS: usize = 100;

#[post("/api/v1/mining_report")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn mining_report(
    data: web::Data<WebcashApplicationState>,
    mining_report_request: web::Json<MiningReportRequest>,
) -> Result<impl Responder> {
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    // TODO: Fill with real data.
    if !mining_report_request.legalese.terms {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Terms of service not accepted."),
            difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        }));
    }

    let preimage_bytes = match base64::decode(&mining_report_request.preimage) {
        Ok(preimage_bytes) => preimage_bytes,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not base64 decode preimage."),
                difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
            }))
        }
    };

    let preimage_as_str = match std::str::from_utf8(&preimage_bytes) {
        Ok(preimage_as_str) => preimage_as_str,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not UTF-8 decode preimage bytes."),
                difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
            }))
        }
    };

    let preimage: PreimageRequest = match serde_json::from_str(preimage_as_str) {
        Ok(preimage) => preimage,
        Err(_) => {
            return Ok(web::Json(MiningReportResponse {
                status: String::from(JSON_STATUS_ERROR),
                error: String::from("Could not JSON decode preimage string."),
                difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
            }))
        }
    };

    if !preimage.legalese.terms {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Terms of service not accepted in preimage JSON."),
            difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        }));
    }

    if preimage.difficulty != webcash_economy.get_difficulty_target_bits() {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Invalid difficulty in preimage JSON."),
            difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        }));
    }

    // TODO: Check validity of PreimageRequest. JSON: {"webcash": ["e95000:secret:<hex>", "e5000:secret:<hex>"], "subsidy": ["e5000:secret:<hex>"], "nonce": 530201, "timestamp": 1651929787.514265, "difficulty": 20, "legalese": {"terms": true}}

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
                difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
            }))
        }
    };

    // TODO: Check the validity of the subsidy. Correct amount? Part of webcash_tokens? Claim and store server operator's tokens.
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
                difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
            }))
        }
    };

    let mining_successful = webcash_economy.create_tokens(&webcash_tokens);
    if !mining_successful {
        return Ok(web::Json(MiningReportResponse {
            status: String::from(JSON_STATUS_ERROR),
            error: String::from("Mining failed."),
            difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        }));
    }
    Ok(web::Json(MiningReportResponse {
        status: String::from(JSON_STATUS_SUCCESS),
        error: String::from(""),
        difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
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
    #[serde(skip_serializing_if = "String::is_empty")]
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

const MAX_HEALTH_CHECK_TOKENS: usize = 100;

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
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", DEFAULT_RUST_LOG);
    }
    pretty_env_logger::init_timed();

    info!("Starting server instance at http://{SERVER_BIND_ADDRESS}:{SERVER_BIND_PORT}/");

    let persist_to_disk = true;
    let webcash_economy = webcash::WebcashEconomy::new(persist_to_disk);
    info!(
        "The economy contains {} unspent webcash (in {} tokens) at startup.",
        webcash_economy.get_total_unspent().separate_with_commas(),
        webcash_economy
            .get_number_of_unspent_tokens()
            .separate_with_commas()
    );
    info!("Set the environment variable RUST_LOG=debug to print debug information.");
    info!("Quit the server with CONTROL-C.");
    let webcash_application_state = web::Data::new(WebcashApplicationState {
        webcash_economy: Mutex::new(webcash_economy),
    });
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
            .service(stats)
    })
    .bind((SERVER_BIND_ADDRESS, SERVER_BIND_PORT))?
    .run()
    .await
}

// End of File
