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
use webcash::{Amount, PublicWebcash, SecretWebcash, WebcashEconomy};

const DEFAULT_RUST_LOG: &str = "info,actix_server=warn";

const SERVER_BIND_ADDRESS: &str = "127.0.0.1";
const SERVER_BIND_PORT: u16 = 8000;

// TODO: Return status_code != 200 when JSON_STATUS_ERROR
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
    if MAX_REPLACEMENT_INPUT_TOKENS < inputs.len() {
        return json_replace_response(JSON_STATUS_ERROR, "Number of inputs exceeds maximum limit.");
    }

    let outputs = &replace_request.new_webcashes;
    if MAX_REPLACEMENT_OUTPUT_TOKENS < outputs.len() {
        return json_replace_response(JSON_STATUS_ERROR, "Number of inputs exceeds maximum limit.");
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
    circulation_formatted: String,
    circulation: u128,
    difficulty_target_bits: u8,
    ratio: f32,
    mining_amount: Amount,
    mining_subsidy_amount: Amount,
    epoch: usize,
    mining_reports: usize,
}

#[get("/stats")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn stats(data: web::Data<WebcashApplicationState>) -> impl Responder {
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    web::Json(StatsResponse {
        circulation_formatted: webcash_economy
            .get_human_readable_total_circulation()
            .separate_with_commas(),
        circulation: webcash_economy.get_human_readable_total_circulation(),
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
    timestamp: serde_json::Number,
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

fn decode_preimage(preimage_request_base64: &str) -> Option<PreimageRequest> {
    let preimage_request_bytes = base64::decode(preimage_request_base64).ok()?;
    let preimage_request_string = std::str::from_utf8(&preimage_request_bytes).ok()?;
    let preimage_request: PreimageRequest = serde_json::from_str(preimage_request_string).ok()?;
    Some(preimage_request)
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

    let preimage_request_base64 = &mining_report_request.preimage;
    let preimage_request = match decode_preimage(preimage_request_base64) {
        Some(preimage_request) => preimage_request,
        None => {
            return json_mining_report_response(
                JSON_STATUS_ERROR,
                "Could not decode preimage request.",
                difficulty_target_bits,
            );
        }
    };

    let preimage_timestamp = match preimage_request.timestamp.as_f64() {
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

    let webcash_tokens = preimage_request.webcash;
    if MAX_MINING_OUTPUT_TOKENS < webcash_tokens.len() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Number of webcash in mining report exceeds maximum limit.",
            difficulty_target_bits,
        );
    }

    let subsidy_tokens = preimage_request.subsidy;
    if MAX_MINING_OUTPUT_SUBSIDY_TOKENS < subsidy_tokens.len() {
        return json_mining_report_response(
            JSON_STATUS_ERROR,
            "Number of subsidy webcash in mining report exceeds maximum limit.",
            difficulty_target_bits,
        );
    }

    let mining_successful = webcash_economy.mine_tokens(
        preimage_request_base64,
        preimage_timestamp,
        &webcash_tokens,
        &subsidy_tokens,
    );
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    tokens: web::Json<Vec<PublicWebcash>>,
) -> impl actix_web::Responder {
    if MAX_HEALTH_CHECK_TOKENS < tokens.len() {
        return json_health_check_response(
            JSON_STATUS_ERROR,
            "Requested number of public webcash to check exceeds maximum limit.",
            std::collections::HashMap::default(),
        );
    }
    let webcash_economy = &mut data.webcash_economy.lock().unwrap();
    let mut results = std::collections::HashMap::<String, HealthCheckSpentResponse>::default();
    let outputs = webcash_economy.get_outputs(&tokens);
    for (token_string, output) in outputs {
        let mut spent: Option<bool> = None;
        let mut amount: Option<Amount> = None;
        if let Some(output) = output {
            spent = Some(output.spent);
            amount = Some(output.amount);
        }
        results.insert(token_string, HealthCheckSpentResponse { spent, amount });
    }

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
        webcash_economy.get_total_unspent().separate_with_spaces(),
        webcash_economy
            .get_number_of_unspent_tokens()
            .separate_with_spaces()
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
