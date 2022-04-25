// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use actix_web::{
    get, http::header::ContentType, post, web, App, HttpResponse, HttpServer, Responder, Result,
};
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

const OPTIONAL_AMOUNT_PREFIX: &str = "e";
const MAX_WEBCASH: i64 = 210_000_000_000;
const WEBCASH_DECIMALS: u32 = 8;
const WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC: &str = "public";
const WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET: &str = "secret";
const HEX_STRING_LENGTH: usize = 64;

const MAX_HEALTH_CHECK_TOKENS: usize = 100;
const MAX_REPLACEMENT_INPUT_TOKENS: usize = 100;
const MAX_REPLACEMENT_OUTPUT_TOKENS: usize = 100;

const JSON_STATUS_SUCCESS: &str = "success";
const JSON_STATUS_ERROR: &str = "error";

#[get("/")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
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

struct WebcashToken {
    amount: Decimal,
    token_kind: WebcashTokenKind,
    hex_string: String,
}

impl WebcashToken {
    fn new(amount: Decimal, token_kind: WebcashTokenKind, hex_string: &str) -> WebcashToken {
        assert!(!amount.is_sign_negative());
        assert!(is_webcash_amount(amount) && is_webcash_amount(amount.normalize()));
        assert!(is_webcash_token_kind_string(&token_kind.to_string()));
        assert!(is_webcash_hex_string(hex_string));
        let webcash = WebcashToken {
            amount: amount.normalize(),
            token_kind,
            hex_string: hex_string.to_string(),
        };
        assert!(is_webcash_token_object(&webcash));
        assert_eq!(webcash.hex_string.len(), HEX_STRING_LENGTH);
        assert_eq!(webcash.hex_string, webcash.hex_string.to_lowercase());
        webcash
    }
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

    let inputs = match parse_webcash_tokens(
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
        .all(|wc| wc.token_kind == WebcashTokenKind::Secret));

    let outputs = match parse_webcash_tokens(
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
        .all(|wc| wc.token_kind == WebcashTokenKind::Secret));

    let total_input = inputs.iter().map(|wc| wc.amount).sum();
    assert!(is_webcash_amount(total_input));
    let total_output = outputs.iter().map(|wc| wc.amount).sum();
    assert!(is_webcash_amount(total_output));
    if total_input != total_output {
        return Ok(json_replace_response(JSON_STATUS_ERROR, "Amount mismatch."));
    }

    // TODO: Atomic data store verification and replacement of tokens.

    Ok(json_replace_response(JSON_STATUS_SUCCESS, ""))
}

#[get("/api/v1/target")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn target() -> impl Responder {
    HttpResponse::Ok().body("target")
}

#[post("/api/v1/mining_report")]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
async fn mining_report() -> impl Responder {
    HttpResponse::Ok().body("mining_report")
}

#[derive(Serialize)]
struct HealthCheckSpentResponse {
    spent: Option<bool>,
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
        match parse_webcash_tokens(&health_check_request, true, MAX_HEALTH_CHECK_TOKENS) {
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
        results.insert(
            webcash_token.to_string(), // TODO: Public or private webcash expected here?
            HealthCheckSpentResponse { spent },
        );
    }
    assert!(results.len() == health_check_request.len());

    Ok(json_health_check_response(JSON_STATUS_SUCCESS, "", results))
}

#[actix_web::main]
#[cfg(not(tarpaulin_include))]
#[allow(clippy::unused_async)]
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

fn parse_webcash_tokens(
    webcash_strings: &[String],
    allow_public_tokens: bool,
    max_tokens: usize,
) -> Result<Vec<WebcashToken>, &str> {
    if webcash_strings.is_empty() {
        return Err("Zero tokens.");
    }
    if webcash_strings.len() > max_tokens {
        return Err("Too many tokens.");
    }
    let mut webcash_tokens = Vec::<WebcashToken>::new();
    for webcash_token_string in webcash_strings {
        let token = match webcash_token_string.parse::<WebcashToken>() {
            Ok(token) => token,
            Err(_) => return Err("Invalid token."),
        };
        assert!(is_webcash_token(webcash_token_string));
        webcash_tokens.push(token);
    }
    assert!(webcash_strings.len() == webcash_tokens.len());
    assert!(webcash_tokens.iter().all(is_webcash_token_object));
    if !allow_public_tokens
        && !webcash_tokens
            .iter()
            .all(|wc| wc.token_kind == WebcashTokenKind::Secret)
    {
        return Err("Public tokens not allowed in this context.");
    }
    let mut unique_hex_strings: Vec<String> = webcash_tokens
        .iter()
        .map(|wc| wc.hex_string.to_string())
        .collect();
    unique_hex_strings.sort();
    unique_hex_strings.dedup();
    if unique_hex_strings.len() != webcash_tokens.len() {
        return Err("Duplicate hex string(s).");
    }
    let total_amount = webcash_tokens.iter().map(|wc| wc.amount).sum();
    if !is_webcash_amount(total_amount) {
        return Err("Invalid amount.");
    }
    Ok(webcash_tokens)
}

#[test]
fn test_parse_webcash_tokens() {
    let valid_tokens_1 = vec![
        "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"
            .to_string(),
        "e1:public:12345678901234567890123456789012345678901234567890123456789abcd3".to_string(),
        "e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4".to_string(),
    ];
    assert!(parse_webcash_tokens(&valid_tokens_1, true, 100).is_ok());
    assert!(parse_webcash_tokens(&valid_tokens_1, false, 100).is_err());
    assert!(parse_webcash_tokens(&valid_tokens_1, true, 4).is_ok());
    assert!(parse_webcash_tokens(&valid_tokens_1, false, 4).is_err());
    assert!(parse_webcash_tokens(&valid_tokens_1, true, 3).is_err());
    assert!(parse_webcash_tokens(&valid_tokens_1, false, 3).is_err());

    let valid_tokens_2 = vec![
        "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"
            .to_string(),
        "e1.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcd3"
            .to_string(),
        "e1.0000:secret:12345678901234567890123456789012345678901234567890123456789abcd4"
            .to_string(),
    ];
    assert!(parse_webcash_tokens(&valid_tokens_2, true, 4).is_ok());
    assert!(parse_webcash_tokens(&valid_tokens_2, false, 4).is_ok());
    assert!(parse_webcash_tokens(&valid_tokens_2, true, 3).is_err());
    assert!(parse_webcash_tokens(&valid_tokens_2, false, 3).is_err());

    let total_amount_too_large_tokens = vec![
        "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e210000000000:secret:12345678901234567890123456789012345678901234567890123456789abcd2"
            .to_string(),
    ];
    assert!(parse_webcash_tokens(&total_amount_too_large_tokens, true, 100).is_err());

    let zero_tokens: Vec<String> = vec![];
    assert!(parse_webcash_tokens(&zero_tokens, true, 100).is_err());

    let invalid_tokens = vec![
        "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e1:public:12345678901234567890123456789012345678901234567890123456789abcd3".to_string(),
        "e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4".to_string(),
        "e210000000000.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"
            .to_string(),
    ];
    assert!(parse_webcash_tokens(&invalid_tokens, true, 100).is_err());
    assert!(parse_webcash_tokens(&invalid_tokens, false, 100).is_err());

    let duplicate_hex_1 = vec![
        "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"
            .to_string(),
        "e1:public:12345678901234567890123456789012345678901234567890123456789abcd3".to_string(),
        "e1:secret:12345678901234567890123456789012345678901234567890123456789abcd1".to_string(),
    ];
    assert!(parse_webcash_tokens(&duplicate_hex_1, true, 100).is_err());
    assert!(parse_webcash_tokens(&duplicate_hex_1, false, 100).is_err());

    let duplicate_hex_2 = vec![
        "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e1:public:12345678901234567890123456789012345678901234567890123456789abcd3".to_string(),
        "e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4".to_string(),
    ];
    assert!(parse_webcash_tokens(&duplicate_hex_2, true, 100).is_err());
    assert!(parse_webcash_tokens(&duplicate_hex_2, false, 100).is_err());

    let duplicate_hex_3 = vec![
        "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"
            .to_string(),
        "e1:public:12345678901234567890123456789012345678901234567890123456789abcd3".to_string(),
        "e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4".to_string(),
    ];
    assert!(parse_webcash_tokens(&duplicate_hex_3, true, 100).is_err());
    assert!(parse_webcash_tokens(&duplicate_hex_3, false, 100).is_err());
}

fn is_webcash_amount(amount: Decimal) -> bool {
    let webcash_min_amount = Decimal::new(1, WEBCASH_DECIMALS);
    let webcash_max_amount = Decimal::new(MAX_WEBCASH, 0);
    if amount < webcash_min_amount {
        return false;
    }
    if amount > webcash_max_amount {
        return false;
    }
    let valid_precision = ((amount * Decimal::new(i64::pow(10, WEBCASH_DECIMALS), 0))
        % Decimal::new(1, 0))
        == Decimal::new(0, 0);
    if !valid_precision {
        return false;
    }
    true
}

#[test]
fn test_decimal_from_str() {
    assert!(Decimal::from_str_exact("Inf").is_err());
    assert!(Decimal::from_str_exact("-Inf").is_err());
    assert!(Decimal::from_str_exact("NaN").is_err());
    assert!(Decimal::from_str_exact("-NaN").is_err());
}

#[test]
fn test_is_webcash_amount() {
    assert!(is_webcash_amount(
        Decimal::from_str_exact("0.00000001").unwrap()
    ));
    assert!(is_webcash_amount(Decimal::from_str_exact("1").unwrap()));
    assert!(is_webcash_amount(
        Decimal::from_str_exact("1.00000001").unwrap()
    ));
    assert!(is_webcash_amount(
        Decimal::from_str_exact("209999999999.99999999").unwrap()
    ));
    assert!(is_webcash_amount(
        Decimal::from_str_exact("210000000000").unwrap()
    ));

    assert!(!is_webcash_amount(Decimal::from_str_exact("0").unwrap()));
    assert!(!is_webcash_amount(
        Decimal::from_str_exact("0.000000001").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str_exact("1.000000001").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str_exact("209999999999.999999989").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str_exact("210000000000.00000001").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str_exact("210000000000.1").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str_exact("210000000001").unwrap()
    ));
    assert!(!is_webcash_amount(Decimal::from_str_exact("-0").unwrap()));
    assert!(!is_webcash_amount(Decimal::from_str_exact("-1").unwrap()));
    assert!(!is_webcash_amount(Decimal::from_str_exact("-1.1").unwrap()));
    assert!(!is_webcash_amount(
        Decimal::from_str_exact("-210000000000").unwrap()
    ));
}

fn parse_webcash_amount(amount_str: &str) -> Option<Decimal> {
    let amount_str =
        if !OPTIONAL_AMOUNT_PREFIX.is_empty() && amount_str.starts_with(OPTIONAL_AMOUNT_PREFIX) {
            &amount_str[OPTIONAL_AMOUNT_PREFIX.len()..]
        } else {
            amount_str
        };
    if !amount_str
        .chars()
        .all(|ch| ('0'..='9').contains(&ch) || ch == '.')
    {
        return None;
    }
    if amount_str.starts_with('0') && !amount_str.starts_with("0.") {
        return None;
    }
    if amount_str.contains('.') {
        let amount_parts: Vec<&str> = amount_str.split('.').collect();
        if amount_parts.len() != 2 {
            return None;
        }
        let integer_part = amount_parts[0];
        if integer_part.is_empty() || integer_part.len() > MAX_WEBCASH.to_string().len() {
            return None;
        }
        let fractional_part = amount_parts[1];
        if fractional_part.is_empty() || fractional_part.len() > WEBCASH_DECIMALS as usize {
            return None;
        }
    } else if amount_str.is_empty() || amount_str.len() > MAX_WEBCASH.to_string().len() {
        return None;
    }
    let amount = match Decimal::from_str_exact(amount_str) {
        Ok(amount) => amount.normalize(),
        Err(_) => unreachable!(),
    };
    assert!(!amount.is_sign_negative());
    assert!(amount.to_string().len() <= amount_str.len());
    if !is_webcash_amount(amount) {
        return None;
    }
    Some(amount)
}

#[derive(PartialEq)]
enum WebcashTokenKind {
    Public,
    Secret,
}

fn parse_webcash_token_kind(webcash_token_kind_str: &str) -> Option<WebcashTokenKind> {
    match webcash_token_kind_str {
        WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC => Some(WebcashTokenKind::Public),
        WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET => Some(WebcashTokenKind::Secret),
        _ => None,
    }
}

fn webcash_token_kind_to_string(token_kind: &WebcashTokenKind) -> &'static str {
    match token_kind {
        WebcashTokenKind::Public => WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC,
        WebcashTokenKind::Secret => WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET,
    }
}

fn is_webcash_token_kind_string(webcash_token_kind_str: &str) -> bool {
    webcash_token_kind_str == WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC
        || webcash_token_kind_str == WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET
}

impl fmt::Display for WebcashTokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", webcash_token_kind_to_string(self))
    }
}

fn is_webcash_hex_string(hex: &str) -> bool {
    hex.len() == HEX_STRING_LENGTH
        && hex
            .chars()
            .all(|ch| ('0'..='9').contains(&ch) || ('a'..='f').contains(&ch))
}

#[test]
fn test_is_webcash_hex_string() {
    assert!(is_webcash_hex_string(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ));
    assert!(is_webcash_hex_string(
        "0ba1c936042f2d6aade5563e9fb319275aec0ee6a262a5a77be01aad99a98cf2"
    ));

    assert!(!is_webcash_hex_string(""));
    assert!(!is_webcash_hex_string("0"));
    assert!(!is_webcash_hex_string("01"));
    assert!(!is_webcash_hex_string(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
    ));
    assert!(!is_webcash_hex_string(
        " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ));
    assert!(!is_webcash_hex_string(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
    ));
    assert!(!is_webcash_hex_string(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
    ));
    assert!(!is_webcash_hex_string(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde "
    ));
    assert!(!is_webcash_hex_string(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
    ));
}

fn parse_webcash_hex_string(hex: &str) -> Option<String> {
    if !is_webcash_hex_string(hex) {
        return None;
    }
    Some(hex.to_string())
}

fn webcash_token_to_string(token: &WebcashToken) -> String {
    assert!(is_webcash_token_object(token));
    format!(
        "e{}:{}:{}",
        token.amount.normalize(),
        token.token_kind,
        token.hex_string
    )
}

#[test]
fn test_webcash_token_to_string() {
    let tokens: Vec<&str> = vec![
	"e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcde",
	"e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde",
	"e1:public:12345678901234567890123456789012345678901234567890123456789abcde",
	"e1:secret:12345678901234567890123456789012345678901234567890123456789abcde",
	"e210000000000.00000000:public:12345678901234567890123456789012345678901234567890123456789abcde",
	"e210000000000.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcde",
	];
    for token in tokens {
        assert!(is_webcash_token(&webcash_token_to_string(
            &parse_webcash_token(token).unwrap()
        )));
        assert!(is_webcash_token(&format!(
            "{}",
            &parse_webcash_token(token).unwrap()
        )));
        assert_eq!(
            webcash_token_to_string(&parse_webcash_token(token).unwrap()),
            format!("{}", &parse_webcash_token(token).unwrap())
        );
    }
}

impl fmt::Display for WebcashToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        assert!(is_webcash_token_object(self));
        write!(f, "{}", webcash_token_to_string(self))
    }
}

fn parse_webcash_token(webcash_token_str: &str) -> Option<WebcashToken> {
    let token_parts: Vec<&str> = webcash_token_str.split(':').collect();
    if token_parts.len() != 3 {
        return None;
    }

    let amount = match parse_webcash_amount(token_parts[0]) {
        Some(amount) => amount,
        None => return None,
    };

    let token_kind = match parse_webcash_token_kind(token_parts[1]) {
        Some(token_kind) => token_kind,
        None => return None,
    };

    let hex_string = match parse_webcash_hex_string(token_parts[2]) {
        Some(hex_string) => hex_string,
        None => return None,
    };

    let webcash = WebcashToken::new(amount, token_kind, &hex_string);
    Some(webcash)
}

impl std::str::FromStr for WebcashToken {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_webcash_token(s).ok_or(format!("'{}' is not a valid value for WebcashToken", s))
    }
}

fn is_webcash_token_object(token: &WebcashToken) -> bool {
    is_webcash_amount(token.amount)
        && is_webcash_token_kind_string(&token.token_kind.to_string())
        && is_webcash_hex_string(&token.hex_string)
}

fn is_webcash_token(webcash_token_str: &str) -> bool {
    let token = match webcash_token_str.parse::<WebcashToken>() {
        Ok(token) => token,
        Err(_) => return false,
    };
    assert!(is_webcash_token_object(&token));
    true
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_is_webcash_token() {
    assert!(is_webcash_token(
        "1.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "1:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e1:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e1.0:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e1:public:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e1.12345678:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e0.1:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e0.00000002:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e210000000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e210000000000.0:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(is_webcash_token(
        "e210000000000.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));

    assert!(!is_webcash_token(""));
    assert!(!is_webcash_token("::"));
    assert!(!is_webcash_token(":::"));
    assert!(!is_webcash_token("e:::"));
    assert!(!is_webcash_token("e1:::"));
    assert!(!is_webcash_token("e1:secret::"));
    assert!(!is_webcash_token(
        "e1::12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(":secret::"));
    assert!(!is_webcash_token(
        "::12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        " 1:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "1:secret:12345678901234567890123456789012345678901234567890123456789abcde "
    ));
    assert!(!is_webcash_token(
        "1:secret:12345678901234567890123456789012345678901234567890123456789abcde:"
    ));
    assert!(!is_webcash_token(
        "1..00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "1.00000001.:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "1.000000010:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "1.000000001:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e1.:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e.1:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e1e1:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e1:private:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e1.123456780:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token("e1.123456780000000000000000000000000000000000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"));
    assert!(!is_webcash_token(
        "e1.123456780:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e1.123456781:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e1.12345678::secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e0:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e00.1:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e01:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e0.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e0.000000010:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e0.000000011:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e210000000000.000000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e210000000000.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e2100000000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e2100000000000.0000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
    assert!(!is_webcash_token(
        "e2100000000000.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
    ));
}

// End of File
