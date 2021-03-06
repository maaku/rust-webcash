// Copyright (c) 2022 Webcash Developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use actix_web::{
    get, http::header::ContentType, post, web, App, HttpResponse, HttpServer, Responder,
};
use thousands::Separable;
#[macro_use]
extern crate log;
use serde::{Deserialize, Serialize};
use webcash::{
    Amount, CheckForDuplicates, PublicWebcash, SecretWebcash, SumAmounts, WebcashEconomy,
    WEBCASH_DECIMALS,
};

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
    webcashes: Vec<SecretWebcash>,
    new_webcashes: Vec<SecretWebcash>,
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
) -> impl Responder {
    if !replace_request.legalese.terms {
        return json_replace_response(JSON_STATUS_ERROR, "Terms of service not accepted.");
    }

    let inputs = &replace_request.webcashes;
    if inputs.is_empty() {
        return json_replace_response(JSON_STATUS_ERROR, "Must specify input webcashes.");
    }
    if MAX_REPLACEMENT_INPUT_TOKENS < inputs.len() {
        return json_replace_response(JSON_STATUS_ERROR, "Number of inputs exceeds maximum limit.");
    }

    let outputs = &replace_request.new_webcashes;
    if outputs.is_empty() {
        return json_replace_response(JSON_STATUS_ERROR, "Must specify output webcashes.");
    }
    if MAX_REPLACEMENT_OUTPUT_TOKENS < outputs.len() {
        return json_replace_response(JSON_STATUS_ERROR, "Number of inputs exceeds maximum limit.");
    }

    if inputs.total_value() != outputs.total_value() {
        return json_replace_response(JSON_STATUS_ERROR, "Amount mismatch.");
    }

    if [inputs.as_slice(), outputs.as_slice()]
        .concat()
        .contains_duplicates()
    {
        return json_replace_response(JSON_STATUS_ERROR, "Duplicate webcash.");
    }

    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    let replacement_successful = webcash_economy.replace_tokens(inputs, outputs);
    if !replacement_successful {
        return json_replace_response(JSON_STATUS_ERROR, "Replacement failed.");
    }
    json_replace_response(JSON_STATUS_SUCCESS, "")
}

#[derive(Serialize)]
struct TargetResponse {
    difficulty_target_bits: u8,
    ratio: f32,
    mining_amount: Amount,
    mining_subsidy_amount: Amount,
    epoch: usize,
}

#[get("/api/v1/target")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn target(data: web::Data<WebcashApplicationState>) -> impl Responder {
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    web::Json(TargetResponse {
        difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        ratio: webcash_economy.get_ratio(),
        mining_amount: webcash_economy.get_mining_amount(),
        mining_subsidy_amount: webcash_economy.get_subsidy_amount(),
        epoch: webcash_economy.get_epoch(),
    })
}

#[derive(Serialize)]
struct StatsResponse {
    circulation_formatted: String, // NOTE: Inexact. Live environment does not use decimals here. Uses integers?
    circulation: u128, // NOTE: Inexact. Live environment does not use decimals here. Uses integers?
    difficulty_target_bits: u8,
    ratio: f32,            // TODO/FIX: float here but string (decimal) in target API call.
    mining_amount: Amount, // NOTE: Live environment has "mining_amount": "50000.0", "mining_subsidy_amount": "2500.00". Different granularity?
    mining_subsidy_amount: Amount, // NOTE: Live environment has "mining_amount": "50000.0", "mining_subsidy_amount": "2500.00". Different granularity?
    epoch: usize,
    mining_reports: usize,
}

#[get("/stats")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn stats(data: web::Data<WebcashApplicationState>) -> impl Responder {
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    web::Json(StatsResponse {
        // NOTE: Emulating Python server here by returning a truncated amount.
        //       Will be inexact in the future.
        circulation_formatted: (webcash_economy.get_total_circulation()
            / 10_u128.pow(WEBCASH_DECIMALS))
        .separate_with_commas(),
        circulation: webcash_economy.get_total_circulation() / 10_u128.pow(WEBCASH_DECIMALS),
        difficulty_target_bits: webcash_economy.get_difficulty_target_bits(),
        ratio: webcash_economy.get_ratio(),
        mining_amount: webcash_economy.get_mining_amount(),
        mining_subsidy_amount: webcash_economy.get_subsidy_amount(),
        epoch: webcash_economy.get_epoch(),
        mining_reports: webcash_economy.get_mining_reports(),
    })
}

#[derive(Deserialize)]
struct MiningReportRequest {
    #[serde(rename = "work")]
    _work: serde_json::Number,
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
    webcash: Vec<SecretWebcash>,
    subsidy: Vec<SecretWebcash>,
    #[serde(rename = "nonce")]
    _nonce: u64,
    timestamp: serde_json::Number,
    difficulty: u32,
    legalese: LegaleseRequest,
}

const MAX_MINING_OUTPUT_TOKENS: usize = 100;
const MAX_MINING_OUTPUT_SUBSIDY_TOKENS: usize = 100;

#[cfg(not(tarpaulin_include))]
#[must_use]
fn json_mining_report_response(
    status_message: &str,
    error_message: &str,
    difficulty_target_bits: u8,
) -> impl actix_web::Responder {
    assert!(status_message == JSON_STATUS_SUCCESS || status_message == JSON_STATUS_ERROR);
    web::Json(MiningReportResponse {
        status: status_message.to_string(),
        error: error_message.to_string(),
        difficulty_target_bits,
    })
}

#[post("/api/v1/mining_report")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn mining_report(
    data: web::Data<WebcashApplicationState>,
    mining_report_request: web::Json<MiningReportRequest>,
) -> impl Responder {
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    let difficulty_target_bits = webcash_economy.get_difficulty_target_bits();
    if !mining_report_request.legalese.terms {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Terms of service not accepted.",
            difficulty_target_bits,
        );
    }

    let preimage_bytes = match base64::decode(&mining_report_request.preimage) {
        Ok(preimage_bytes) => preimage_bytes,
        Err(_) => {
            return json_mining_report_response(
                JSON_STATUS_ERROR,
                "Could not base64 decode preimage.",
                difficulty_target_bits,
            );
        }
    };

    let preimage_as_str = match std::str::from_utf8(&preimage_bytes) {
        Ok(preimage_as_str) => preimage_as_str,
        Err(_) => {
            return json_mining_report_response(
                JSON_STATUS_ERROR,
                "Could not UTF-8 decode preimage bytes.",
                difficulty_target_bits,
            );
        }
    };

    let preimage: PreimageRequest = match serde_json::from_str(preimage_as_str) {
        Ok(preimage) => preimage,
        Err(_) => {
            return json_mining_report_response(
                JSON_STATUS_ERROR,
                "Could not JSON decode preimage string.",
                difficulty_target_bits,
            );
        }
    };

    // TODO: Relevant to check? We've already checked the legalese once in this request above.
    if !preimage.legalese.terms {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Terms of service not accepted in preimage JSON.",
            difficulty_target_bits,
        );
    }

    // TODO: Relevant to check? The target difficulty is not relevant as long as the achieved difficulty is sufficient?
    if preimage.difficulty != u32::from(difficulty_target_bits) {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Invalid difficulty in preimage JSON.",
            difficulty_target_bits,
        );
    }

    let preimage_timestamp = match preimage.timestamp.as_f64() {
        Some(preimage_timestamp) => preimage_timestamp,
        None => {
            return json_mining_report_response(
                JSON_STATUS_ERROR,
                "Could not convert preimage timestamp to f64.",
                difficulty_target_bits,
            );
        }
    };
    #[allow(clippy::cast_possible_truncation)]
    let preimage_timestamp = preimage_timestamp.round() as i64;
    if !webcash_economy.is_valid_proof_of_work(&mining_report_request.preimage, preimage_timestamp)
    {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Invalid proof of work.",
            difficulty_target_bits,
        );
    }

    // TODO: Check that subsidy token(s) is a subset of webcash tokens. JSON: {"webcash": ["e95000:secret:<hex>", "e5000:secret:<hex>"], "subsidy": ["e5000:secret:<hex>"], "nonce": 530201, "timestamp": 1651929787.514265, "difficulty": 20, "legalese": {"terms": true}}
    let webcash_tokens = preimage.webcash;
    if webcash_tokens.contains_duplicates() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Duplicate webcash in mining report.",
            difficulty_target_bits,
        );
    }
    if MAX_MINING_OUTPUT_TOKENS < webcash_tokens.len() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Number of webcash in mining report exceeds maximum limit.",
            difficulty_target_bits,
        );
    }

    let mining_amount = webcash_tokens.total_value();
    if mining_amount.is_none() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Missing webcash in mining report.",
            difficulty_target_bits,
        );
    }
    let mining_amount = mining_amount.unwrap();
    if mining_amount != webcash_economy.get_mining_amount() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Unexpected mining amount.",
            difficulty_target_bits,
        );
    }

    // TODO: Claim and store server operator's tokens.
    let subsidy_tokens = preimage.subsidy;
    if subsidy_tokens.contains_duplicates() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Duplicate webcash in mining report.",
            difficulty_target_bits,
        );
    }
    if MAX_MINING_OUTPUT_SUBSIDY_TOKENS < subsidy_tokens.len() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Number of subsidy webcash in mining report exceeds maximum limit.",
            difficulty_target_bits,
        );
    }

    let subsidy_amount = subsidy_tokens.total_value();
    if subsidy_amount.is_none() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Missing subsidy in mining report.",
            difficulty_target_bits,
        );
    }
    let subsidy_amount = subsidy_amount.unwrap();
    if subsidy_amount != webcash_economy.get_subsidy_amount() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Unexpected subsidy amount.",
            difficulty_target_bits,
        );
    }

    assert_eq!(mining_amount, webcash_economy.get_mining_amount());
    assert_eq!(subsidy_amount, webcash_economy.get_subsidy_amount());
    assert!(subsidy_amount <= mining_amount);
    assert_eq!(preimage.difficulty, u32::from(difficulty_target_bits));

    // TODO: Rename create_tokens as mine_tokens. In mine_tokens: add check for mining amounts, etc. Add all checks above. Remove public access to create_tokens.
    let mining_successful = webcash_economy.create_tokens(&webcash_tokens);
    if !mining_successful {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Mining failed.",
            difficulty_target_bits,
        );
    }
    json_mining_report_response(JSON_STATUS_SUCCESS, "", difficulty_target_bits)
}

#[derive(Serialize)]
struct HealthCheckSpentResponse {
    spent: Option<bool>,
    amount: Option<Amount>,
}

#[derive(Serialize)]
struct HealthCheckResponse {
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    results: std::collections::HashMap<String, HealthCheckSpentResponse>,
}

#[cfg(not(tarpaulin_include))]
#[must_use]
fn json_health_check_response(
    status_message: &str,
    error_message: &str,
    results: std::collections::HashMap<String, HealthCheckSpentResponse>,
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
    health_check_request: web::Json<Vec<PublicWebcash>>,
) -> impl actix_web::Responder {
    if MAX_HEALTH_CHECK_TOKENS < health_check_request.len() {
        return json_health_check_response(
            JSON_STATUS_ERROR,
            "Requested number of public webcash to check exceeds maximum limit.",
            std::collections::HashMap::default(),
        );
    }
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    let mut results = std::collections::HashMap::<String, HealthCheckSpentResponse>::default();
    // TODO: Move this to separate method in WebcashEconomy. Remove public access for get_using_public_token.
    for public_webcash_token in health_check_request.iter() {
        let mut spent: Option<bool> = None;
        let mut amount: Option<Amount> = None;
        if let Some(amount_state) = webcash_economy.get_using_public_token(public_webcash_token) {
            spent = Some(amount_state.spent);
            amount = Some(amount_state.amount);
        }
        results.insert(
            public_webcash_token.to_string(),
            HealthCheckSpentResponse { spent, amount },
        );
    }
    assert!(results.len() == health_check_request.len());

    json_health_check_response(JSON_STATUS_SUCCESS, "", results)
}

struct WebcashApplicationState {
    webcash_economy: std::sync::Mutex<WebcashEconomy>,
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
    let webcash_economy = WebcashEconomy::new(persist_to_disk);
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
        webcash_economy: std::sync::Mutex::new(webcash_economy),
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
