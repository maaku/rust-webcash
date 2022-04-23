// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use actix_web::{
    get, http::header::ContentType, post, web, App, HttpResponse, HttpServer, Responder, Result,
};
use core::*;
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

const OPTIONAL_AMOUNT_PREFIX: &str = "e";
const MAX_WEBCASH: i64 = 210_000_000_000;
const WEBCASH_DECIMALS: u32 = 8;
const WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC: &str = "public";
const WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET: &str = "secret";
const HEX_STRING_LENGTH: usize = 64;
const MAX_INPUTS_OR_OUTPUTS: usize = 100;

const JSON_STATUS_SUCCESS: &str = "success";
const JSON_STATUS_ERROR: &str = "error";

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[get("/terms")]
async fn terms_html() -> impl Responder {
    // FIXME: This won't build on windows.
    // We should use OS-dependent path separators.
    let terms = include_str!("../../terms/terms.html");
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(terms)
}

#[get("/terms/text")]
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

#[derive(Deserialize)]
struct ReplaceRequest {
    legalese: bool,
    webcashes: Vec<String>,
    new_webcashes: Vec<String>,
}

#[derive(Serialize)]
struct ReplaceResponse {
    status: String,
    error: String,
}

fn json_response(status_message: &str, error_message: &str) -> Result<impl Responder> {
    assert!(status_message == JSON_STATUS_SUCCESS || status_message == JSON_STATUS_ERROR);
    Ok(web::Json(ReplaceResponse {
        status: status_message.to_string(),
        error: error_message.to_string(),
    }))
}

#[post("/api/v1/replace")]
async fn replace(replace_request: web::Json<ReplaceRequest>) -> Result<impl Responder> {
    if !replace_request.legalese {
        return json_response(JSON_STATUS_ERROR, "Legalese not accepted.");
    }

    let inputs = match parse_webcash_tokens_as_inputs_or_outputs(&replace_request.webcashes) {
        Ok(inputs) => inputs,
        Err(_) => return json_response(JSON_STATUS_ERROR, "Invalid input(s)."),
    };
    assert_eq!(inputs.len(), replace_request.webcashes.len());

    let outputs = match parse_webcash_tokens_as_inputs_or_outputs(&replace_request.new_webcashes) {
        Ok(outputs) => outputs,
        Err(_) => return json_response(JSON_STATUS_ERROR, "Invalid output(s)."),
    };
    assert_eq!(outputs.len(), replace_request.new_webcashes.len());

    let total_input = inputs.iter().map(|wc| wc.amount).sum();
    assert!(is_webcash_amount(total_input));
    let total_output = outputs.iter().map(|wc| wc.amount).sum();
    assert!(is_webcash_amount(total_output));
    if total_input != total_output {
        return json_response(JSON_STATUS_ERROR, "Amount mismatch.");
    }

    // TODO: Atomic data store verification and replacement of tokens.

    json_response(JSON_STATUS_SUCCESS, "")
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

fn parse_webcash_tokens_as_inputs_or_outputs(
    webcash_strings: &Vec<String>,
) -> Result<Vec<WebcashToken>, &str> {
    if webcash_strings.is_empty() {
        return Err("Zero tokens.");
    }
    if webcash_strings.len() > MAX_INPUTS_OR_OUTPUTS {
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
    let mut locally_consumed_hex_strings = HashSet::new();
    for webcash_token in &webcash_tokens {
        assert!(is_webcash_amount(webcash_token.amount));
        assert!(is_webcash_hex_string(&webcash_token.hex_string));
        if webcash_token.token_kind != WebcashTokenKind::Secret {
            return Err("Unexpected token type.");
        }
        if locally_consumed_hex_strings.contains(&webcash_token.hex_string) {
            return Err("Duplicate hex string.");
        }
        locally_consumed_hex_strings.insert(webcash_token.hex_string.to_string());
    }
    let total_amount = webcash_tokens.iter().map(|wc| wc.amount).sum();
    if !is_webcash_amount(total_amount) {
        return Err("Invalid amount.");
    }
    Ok(webcash_tokens)
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
fn test_is_webcash_amount() {
    assert!(is_webcash_amount(Decimal::from_str("0.00000001").unwrap()));
    assert!(is_webcash_amount(Decimal::from_str("1").unwrap()));
    assert!(is_webcash_amount(Decimal::from_str("1.00000001").unwrap()));
    assert!(is_webcash_amount(
        Decimal::from_str("209999999999.99999999").unwrap()
    ));
    assert!(is_webcash_amount(
        Decimal::from_str("210000000000").unwrap()
    ));

    assert!(!is_webcash_amount(Decimal::from_str("0").unwrap()));
    assert!(!is_webcash_amount(
        Decimal::from_str("0.000000001").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str("1.000000001").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str("209999999999.999999989").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str("210000000000.00000001").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str("210000000000.1").unwrap()
    ));
    assert!(!is_webcash_amount(
        Decimal::from_str("210000000001").unwrap()
    ));

    assert!(!is_webcash_amount(Decimal::from_str("-0").unwrap()));
    assert!(!is_webcash_amount(Decimal::from_str("-1").unwrap()));
    assert!(!is_webcash_amount(Decimal::from_str("-1.1").unwrap()));
    assert!(!is_webcash_amount(
        Decimal::from_str("-210000000000").unwrap()
    ));
}

fn parse_webcash_amount(amount_str: &str) -> Option<Decimal> {
    let amount_str =
        if OPTIONAL_AMOUNT_PREFIX.len() > 0 && amount_str.starts_with(OPTIONAL_AMOUNT_PREFIX) {
            &amount_str[OPTIONAL_AMOUNT_PREFIX.len()..]
        } else {
            amount_str
        };
    if !amount_str
        .chars()
        .all(|ch| (ch >= '0' && ch <= '9') || ch == '.')
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
        if !(integer_part.len() >= 1 && integer_part.len() <= MAX_WEBCASH.to_string().len()) {
            return None;
        }
        let fractional_part = amount_parts[1];
        if !(fractional_part.len() >= 1 && fractional_part.len() <= WEBCASH_DECIMALS as usize) {
            return None;
        }
    } else {
        if !(amount_str.len() >= 1 && amount_str.len() <= MAX_WEBCASH.to_string().len()) {
            return None;
        }
    }
    let amount = match Decimal::from_str(amount_str) {
        Ok(amount) => amount.normalize(),
        Err(_) => return None,
    };
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

fn parse_webcash_token_kind(webcash_token_str: &str) -> Option<WebcashTokenKind> {
    match webcash_token_str {
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

impl fmt::Display for WebcashTokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", webcash_token_kind_to_string(self))
    }
}

fn is_webcash_hex_string(hex: &str) -> bool {
    hex.len() == HEX_STRING_LENGTH
        && hex
            .chars()
            .all(|ch| (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))
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
    format!(
        "e{}:{}:{}",
        token.amount.normalize(),
        token.token_kind,
        token.hex_string
    )
}

impl fmt::Display for WebcashToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    let webcash = WebcashToken {
        amount: amount,
        token_kind: token_kind,
        hex_string: hex_string,
    };
    assert!(is_webcash_amount(webcash.amount));
    assert_eq!(
        webcash.amount.to_string(),
        webcash.amount.normalize().to_string()
    );
    assert!(
        webcash.token_kind.to_string() == WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC
            || webcash.token_kind.to_string() == WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET
    );
    assert_eq!(webcash.hex_string.len(), HEX_STRING_LENGTH);
    assert_eq!(webcash.hex_string, webcash.hex_string.to_lowercase());
    Some(webcash)
}

impl std::str::FromStr for WebcashToken {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_webcash_token(s).ok_or(format!("'{}' is not a valid value for WebcashToken", s))
    }
}

fn is_webcash_token(webcash_token_str: &str) -> bool {
    webcash_token_str.parse::<WebcashToken>().is_ok()
}

#[test]
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
