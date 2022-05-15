use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use thousands::Separable;
#[macro_use]
extern crate log;
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const OPTIONAL_AMOUNT_PREFIX: &str = "e";
const MAX_WEBCASH: i64 = 210_000_000_000;
const WEBCASH_DECIMALS: u32 = 8;

const MINING_REPORTS_PER_EPOCH: u32 = 525_000;
const MINING_AMOUNT_IN_FIRST_EPOCH: i64 = 200_000;
const MINING_SUBSIDY_FRACTION: &str = "0.05";

const WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC: &str = "public";
const WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET: &str = "secret";

const HEX_STRING_LENGTH: usize = 64;

const WEBCASH_ECONOMY_JSON_FILE: &str = "webcashd.json";

#[derive(PartialEq, Clone, Debug)]
pub enum WebcashTokenKind {
    Public,
    Secret,
}

#[derive(Clone)]
pub struct WebcashToken {
    pub amount: Decimal,
    pub token_kind: WebcashTokenKind,
    pub hex_string: String,
}

impl WebcashToken {
    #[must_use]
    pub fn to_public(&self) -> WebcashToken {
        assert!(self.token_kind == WebcashTokenKind::Secret);
        WebcashToken {
            amount: self.amount,
            token_kind: WebcashTokenKind::Public,
            hex_string: secret_to_public(&self.hex_string),
        }
    }
}

#[must_use]
fn contains_duplicates(webcash_tokens: &Vec<WebcashToken>) -> bool {
    let mut unique_hex_strings: Vec<String> = webcash_tokens
        .iter()
        .map(|wc| wc.hex_string.to_string())
        .collect();
    unique_hex_strings.sort();
    unique_hex_strings.dedup();
    unique_hex_strings.len() != webcash_tokens.len()
}

#[must_use]
fn are_syntactically_valid_tokens(
    tokens: &Vec<WebcashToken>,
    allowed_token_type: &WebcashTokenKind,
) -> bool {
    if !tokens.iter().all(|wc| wc.token_kind == *allowed_token_type) {
        return false;
    }
    if !tokens.iter().all(is_webcash_token_object) {
        return false;
    }
    if contains_duplicates(tokens) {
        return false;
    }
    let total_amount = tokens.iter().map(|wc| wc.amount).sum();
    if !is_webcash_amount(total_amount) {
        return false;
    }
    true
}

pub fn parse_webcash_tokens(
    webcash_strings: &[String],
    allowed_token_type: &WebcashTokenKind,
    max_tokens: usize,
) -> Result<Vec<WebcashToken>, String> {
    if webcash_strings.is_empty() {
        return Err(String::from("Zero tokens."));
    }
    if webcash_strings.len() > max_tokens {
        return Err(String::from("Too many tokens."));
    }
    let mut webcash_tokens = Vec::<WebcashToken>::default();
    for webcash_token_string in webcash_strings {
        let token = match webcash_token_string.parse::<WebcashToken>() {
            Ok(token) => token,
            Err(_) => return Err(String::from("Invalid token.")),
        };
        assert!(is_webcash_token(webcash_token_string));
        assert!(is_webcash_token(&token.to_string()));
        webcash_tokens.push(token);
    }
    assert!(webcash_strings.len() == webcash_tokens.len());
    if !are_syntactically_valid_tokens(&webcash_tokens, allowed_token_type) {
        return Err(String::from("Invalid tokens."));
    }
    Ok(webcash_tokens)
}

impl fmt::Display for WebcashTokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", webcash_token_kind_to_string(self))
    }
}

impl fmt::Display for WebcashToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        assert!(is_webcash_token_object(self));
        write!(f, "{}", webcash_token_to_string(self))
    }
}

impl std::str::FromStr for WebcashToken {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_webcash_token(s).ok_or(format!("'{s}' is not a valid value for WebcashToken"))
    }
}

#[must_use]
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

#[must_use]
fn is_webcash_hex_string(hex: &str) -> bool {
    hex.len() == HEX_STRING_LENGTH
        && hex
            .chars()
            .all(|ch| ('0'..='9').contains(&ch) || ('a'..='f').contains(&ch))
}

#[must_use]
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
    let amount = Decimal::from_str_exact(amount_str).ok()?;
    assert!(!amount.is_sign_negative());
    assert!(amount.to_string().len() <= amount_str.len());
    if !is_webcash_amount(amount) {
        return None;
    }
    Some(amount)
}

#[must_use]
fn parse_webcash_hex_string(hex: &str) -> Option<String> {
    if !is_webcash_hex_string(hex) {
        return None;
    }
    Some(hex.to_string())
}

#[must_use]
fn parse_webcash_token_kind(webcash_token_kind_str: &str) -> Option<WebcashTokenKind> {
    match webcash_token_kind_str {
        WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC => Some(WebcashTokenKind::Public),
        WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET => Some(WebcashTokenKind::Secret),
        _ => None,
    }
}

#[must_use]
fn webcash_token_kind_to_string(token_kind: &WebcashTokenKind) -> String {
    match token_kind {
        WebcashTokenKind::Public => String::from(WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC),
        WebcashTokenKind::Secret => String::from(WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET),
    }
}

#[must_use]
fn is_webcash_token_kind_string(webcash_token_kind_str: &str) -> bool {
    webcash_token_kind_str == WEBCASH_TOKEN_KIND_IDENTIFIER_PUBLIC
        || webcash_token_kind_str == WEBCASH_TOKEN_KIND_IDENTIFIER_SECRET
}

impl WebcashToken {
    #[must_use]
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

#[must_use]
fn is_webcash_token_object(token: &WebcashToken) -> bool {
    is_webcash_amount(token.amount)
        && is_webcash_token_kind_string(&token.token_kind.to_string())
        && is_webcash_hex_string(&token.hex_string)
}

#[must_use]
fn is_webcash_token(webcash_token_str: &str) -> bool {
    let token = match webcash_token_str.parse::<WebcashToken>() {
        Ok(token) => token,
        Err(_) => return false,
    };
    assert!(is_webcash_token_object(&token));
    true
}

#[must_use]
fn parse_webcash_token(webcash_token_str: &str) -> Option<WebcashToken> {
    let token_parts: Vec<&str> = webcash_token_str.split(':').collect();
    if token_parts.len() != 3 {
        return None;
    }

    let amount = parse_webcash_amount(token_parts[0])?;
    let token_kind = parse_webcash_token_kind(token_parts[1])?;
    let hex_string = parse_webcash_hex_string(token_parts[2])?;

    let webcash = WebcashToken::new(amount, token_kind, &hex_string);
    Some(webcash)
}

#[must_use]
fn webcash_token_to_string(token: &WebcashToken) -> String {
    assert!(is_webcash_token_object(token));
    format!(
        "e{}:{}:{}",
        token.amount.normalize(),
        token.token_kind,
        token.hex_string
    )
}

#[must_use]
fn secret_to_public(secret_value: &str) -> String {
    assert_eq!(secret_value.len(), HEX_STRING_LENGTH);
    assert!(is_webcash_hex_string(secret_value));
    let hash = Sha256::digest(secret_value);
    let hex_hash = format!("{hash:x}");
    assert_eq!(hex_hash.len(), HEX_STRING_LENGTH);
    assert!(is_webcash_hex_string(&hex_hash));
    hex_hash
}

#[derive(Deserialize, Serialize)]
pub struct AmountState {
    pub amount: Decimal,
    pub spent: bool,
}

// https://github.com/serde-rs/serde/issues/368
fn serde_default_literals_workaround_default_true() -> bool {
    true
}

#[derive(Deserialize, Serialize)]
pub struct WebcashEconomy {
    public_hash_to_amount_state: HashMap<String, AmountState>,
    #[serde(skip, default = "serde_default_literals_workaround_default_true")]
    persist_to_disk: bool,
}

const DUMMY_VALUE_MINING_REPORTS: u32 = 1_000_000;
const DUMMY_VALUE_DIFFICULTY_TARGET_BITS: u8 = 20;
const DUMMY_VALUE_RATIO: &str = "1.0001";

impl WebcashEconomy {
    #[must_use]
    pub fn get_mining_reports(&self) -> u32 {
        DUMMY_VALUE_MINING_REPORTS
    }

    #[must_use]
    pub fn get_difficulty_target_bits(&self) -> u8 {
        DUMMY_VALUE_DIFFICULTY_TARGET_BITS
    }

    #[must_use]
    pub fn get_ratio(&self) -> Decimal {
        decimal(DUMMY_VALUE_RATIO)
    }

    #[must_use]
    pub fn new(persist_to_disk: bool) -> WebcashEconomy {
        let mut webcash_economy = WebcashEconomy {
            public_hash_to_amount_state: HashMap::default(),
            persist_to_disk,
        };
        if webcash_economy.persist_to_disk {
            webcash_economy.read_from_disk();
            webcash_economy.sync_to_disk();
        }
        webcash_economy
    }

    #[must_use]
    pub fn get_total_unspent(&self) -> Decimal {
        let now = std::time::Instant::now();
        let total_unspent = self
            .public_hash_to_amount_state
            .values()
            .filter(|amount_state| !amount_state.spent)
            .map(|amount_state| amount_state.amount)
            .sum::<Decimal>()
            .normalize();
        trace!(
            "Calculating total unspent webcash took {} ms.",
            now.elapsed().as_millis()
        );
        total_unspent
    }

    #[must_use]
    pub fn get_number_of_unspent_tokens(&self) -> usize {
        let now = std::time::Instant::now();
        let number_of_unspent_tokens = self
            .public_hash_to_amount_state
            .values()
            .filter(|amount_state| !amount_state.spent)
            .count();
        trace!(
            "Calculating number of unspent tookens took {} ms.",
            now.elapsed().as_millis()
        );
        number_of_unspent_tokens
    }

    #[must_use]
    pub fn get_using_public_token(&self, public_token: &WebcashToken) -> Option<&AmountState> {
        assert!(public_token.token_kind == WebcashTokenKind::Public);
        self.public_hash_to_amount_state
            .get(&public_token.hex_string)
    }

    #[must_use]
    fn get_using_secret_token(&self, secret_token: &WebcashToken) -> Option<&AmountState> {
        assert!(secret_token.token_kind == WebcashTokenKind::Secret);
        self.get_using_public_token(&secret_token.to_public())
    }

    #[must_use]
    fn is_unspent_secret_token_with_correct_amount(&self, secret_token: &WebcashToken) -> bool {
        if secret_token.token_kind != WebcashTokenKind::Secret {
            return false;
        }
        let amount_state = match self.get_using_secret_token(secret_token) {
            Some(amount_state) => amount_state,
            None => return false,
        };
        if amount_state.amount != secret_token.amount {
            return false;
        }
        if amount_state.spent {
            return false;
        }
        true
    }

    #[must_use]
    fn are_unspent_valid_input_tokens(&self, secret_input_tokens: &Vec<WebcashToken>) -> bool {
        if !are_syntactically_valid_tokens(secret_input_tokens, &WebcashTokenKind::Secret) {
            return false;
        }
        if !secret_input_tokens
            .iter()
            .all(|wc| self.is_unspent_secret_token_with_correct_amount(wc))
        {
            return false;
        }
        true
    }

    #[must_use]
    fn is_valid_output_token_with_non_taken_hash(&self, secret_token: &WebcashToken) -> bool {
        if secret_token.token_kind != WebcashTokenKind::Secret {
            return false;
        }
        self.get_using_secret_token(secret_token).is_none()
    }

    #[must_use]
    fn are_valid_output_tokens_with_non_taken_hashes(
        &self,
        secret_output_tokens: &Vec<WebcashToken>,
    ) -> bool {
        if !are_syntactically_valid_tokens(secret_output_tokens, &WebcashTokenKind::Secret) {
            return false;
        }
        if !secret_output_tokens
            .iter()
            .all(|wc| self.is_valid_output_token_with_non_taken_hash(wc))
        {
            return false;
        }
        true
    }

    fn print_token_summary(&self) {
        if !log_enabled!(log::Level::Debug) {
            return;
        }
        debug!(
            "[economy] Total unspent: {} (in {} tokens)",
            self.get_total_unspent().separate_with_commas(),
            self.get_number_of_unspent_tokens().separate_with_commas(),
        );
    }

    fn create_token(&mut self, secret_webcash_token: &WebcashToken) {
        assert_eq!(secret_webcash_token.token_kind, WebcashTokenKind::Secret);
        let old_value = self.public_hash_to_amount_state.insert(
            secret_webcash_token.to_public().hex_string,
            AmountState {
                amount: secret_webcash_token.amount,
                spent: false,
            },
        );
        assert!(old_value.is_none());
        debug!(
            "[diff: +] Token of amount {} created",
            secret_webcash_token.amount.separate_with_commas()
        );
    }

    #[must_use]
    pub fn create_tokens(&mut self, secret_outputs: &Vec<WebcashToken>) -> bool {
        let total_unspent_before = self.get_total_unspent();
        if !self.are_valid_output_tokens_with_non_taken_hashes(secret_outputs) {
            return false;
        }
        for secret_output in secret_outputs {
            self.create_token(secret_output);
        }
        assert_eq!(
            self.get_total_unspent() - total_unspent_before,
            secret_outputs.iter().map(|wc| wc.amount).sum::<Decimal>()
        );
        if self.persist_to_disk {
            self.sync_to_disk();
        }
        self.print_token_summary();
        true
    }

    fn read_from_disk(&mut self) {
        assert!(self.persist_to_disk);
        if !std::path::Path::new(WEBCASH_ECONOMY_JSON_FILE).exists() {
            return;
        }
        let file = File::open(WEBCASH_ECONOMY_JSON_FILE).unwrap();
        let reader = BufReader::new(file);
        let webcash_economy: WebcashEconomy = serde_json::from_reader(reader).unwrap();
        *self = webcash_economy;
    }

    fn sync_to_disk(&self) {
        assert!(self.persist_to_disk);
        let now = std::time::Instant::now();
        let temporary_filename = format!("{}.{}", WEBCASH_ECONOMY_JSON_FILE, std::process::id());
        let file = File::create(&temporary_filename).unwrap();
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, self).unwrap();
        std::fs::rename(temporary_filename, WEBCASH_ECONOMY_JSON_FILE).unwrap();
        trace!("Sync to disk took {} ms.", now.elapsed().as_millis());
    }

    fn mark_as_spent(&mut self, secret_webcash_token: &WebcashToken) {
        assert_eq!(secret_webcash_token.token_kind, WebcashTokenKind::Secret);
        assert!(self.is_unspent_secret_token_with_correct_amount(secret_webcash_token));
        let amount_state: &mut AmountState = self
            .public_hash_to_amount_state
            .get_mut(&secret_webcash_token.to_public().hex_string)
            .unwrap();
        assert_eq!(amount_state.amount, secret_webcash_token.amount);
        assert!(!amount_state.spent);
        amount_state.spent = true;
        debug!(
            "[diff: -] Token of amount {} marked as spent",
            amount_state.amount.separate_with_commas()
        );
    }

    #[must_use]
    pub fn replace_tokens(
        &mut self,
        secret_inputs: &Vec<WebcashToken>,
        secret_outputs: &Vec<WebcashToken>,
    ) -> bool {
        let total_unspent_before = self.get_total_unspent();
        if !self.are_unspent_valid_input_tokens(secret_inputs) {
            return false;
        }
        if !self.are_valid_output_tokens_with_non_taken_hashes(secret_outputs) {
            return false;
        }
        if contains_duplicates(&[secret_inputs.as_slice(), secret_outputs.as_slice()].concat()) {
            return false;
        }
        if secret_inputs.iter().map(|wc| wc.amount).sum::<Decimal>()
            != secret_outputs.iter().map(|wc| wc.amount).sum::<Decimal>()
        {
            return false;
        }
        for secret_input in secret_inputs {
            self.mark_as_spent(secret_input);
        }
        let replacement_tokens_created = self.create_tokens(secret_outputs);
        assert!(
            replacement_tokens_created,
            "Replacement tokens could not be created. This should never happen."
        );
        assert_eq!(total_unspent_before, self.get_total_unspent());
        if self.persist_to_disk {
            self.sync_to_disk();
        }
        // self.print_token_summary() called in create_tokens above.
        true
    }
}

// TODO: How to handle zero return value case (in the future when no mining reward))? Is not a valid webcash amount.
fn mining_amount_per_mining_report_in_epoch(epoch: u32) -> Decimal {
    if epoch >= 63 {
        return Decimal::new(0, 0);
    }
    (Decimal::new(MINING_AMOUNT_IN_FIRST_EPOCH, 0) / Decimal::new(i64::pow(2, epoch), 0))
        .round_dp(WEBCASH_DECIMALS)
        .normalize()
}

// TODO: How to handle zero return value case (in the future when no mining reward))? Is not a valid webcash amount.
#[must_use]
pub fn mining_amount_for_mining_report(mining_report_number: u32) -> Decimal {
    assert!(mining_report_number >= 1);
    mining_amount_per_mining_report_in_epoch(epoch(mining_report_number))
}

// TODO: How to handle zero return value case? Is not a valid webcash amount.
#[must_use]
pub fn mining_subsidy_amount_for_mining_report(mining_report_number: u32) -> Decimal {
    assert!(mining_report_number >= 1);
    (mining_amount_for_mining_report(mining_report_number) * decimal(MINING_SUBSIDY_FRACTION))
        .round_dp(WEBCASH_DECIMALS)
        .normalize()
}

#[must_use]
pub fn epoch(mining_report_number: u32) -> u32 {
    assert!(mining_report_number >= 1);
    (mining_report_number - 1) / MINING_REPORTS_PER_EPOCH
}

#[must_use]
pub fn total_circulation(mining_report_number: u32) -> Decimal {
    assert!(mining_report_number >= 1);
    let mut total_circulation = Decimal::default();
    let mut mining_reports_in_current_epoch = mining_report_number;
    for past_epoch in 0..epoch(mining_report_number) {
        total_circulation += mining_amount_per_mining_report_in_epoch(past_epoch)
            * Decimal::new(i64::from(MINING_REPORTS_PER_EPOCH), 0);
        mining_reports_in_current_epoch -= MINING_REPORTS_PER_EPOCH;
    }
    total_circulation += mining_amount_per_mining_report_in_epoch(epoch(mining_report_number))
        * Decimal::new(i64::from(mining_reports_in_current_epoch), 0);
    assert!(is_webcash_amount(total_circulation));
    total_circulation
}

fn decimal(str: &str) -> Decimal {
    Decimal::from_str_exact(str).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_to_public() {
        assert_eq!(
            secret_to_public("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
            "d7914fe546b684688bb95f4f888a92dfc680603a75f23eb823658031fff766d9"
        );
        assert_eq!(
            secret_to_public("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
            "049da052634feb56ce6ec0bc648c672011edff1cb272b53113bbc90a8f00249c"
        );
    }

    #[test]
    fn test_parse_webcash_tokens() {
        let valid_secret_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert!(
            parse_webcash_tokens(&valid_secret_tokens, &WebcashTokenKind::Public, 100).is_err()
        );
        assert!(parse_webcash_tokens(&valid_secret_tokens, &WebcashTokenKind::Secret, 100).is_ok());
        assert!(parse_webcash_tokens(&valid_secret_tokens, &WebcashTokenKind::Public, 4).is_err());
        assert!(parse_webcash_tokens(&valid_secret_tokens, &WebcashTokenKind::Secret, 4).is_ok());
        assert!(parse_webcash_tokens(&valid_secret_tokens, &WebcashTokenKind::Public, 3).is_err());
        assert!(parse_webcash_tokens(&valid_secret_tokens, &WebcashTokenKind::Secret, 3).is_err());

        let valid_public_tokens = vec![
            String::from("e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:public:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:public:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert!(parse_webcash_tokens(&valid_public_tokens, &WebcashTokenKind::Public, 100).is_ok());
        assert!(
            parse_webcash_tokens(&valid_public_tokens, &WebcashTokenKind::Secret, 100).is_err()
        );
        assert!(parse_webcash_tokens(&valid_public_tokens, &WebcashTokenKind::Public, 4).is_ok());
        assert!(parse_webcash_tokens(&valid_public_tokens, &WebcashTokenKind::Secret, 4).is_err());
        assert!(parse_webcash_tokens(&valid_public_tokens, &WebcashTokenKind::Public, 3).is_err());
        assert!(parse_webcash_tokens(&valid_public_tokens, &WebcashTokenKind::Secret, 3).is_err());

        let valid_mixed_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:public:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert!(parse_webcash_tokens(&valid_mixed_tokens, &WebcashTokenKind::Public, 100).is_err());
        assert!(parse_webcash_tokens(&valid_mixed_tokens, &WebcashTokenKind::Secret, 100).is_err());
        assert!(parse_webcash_tokens(&valid_mixed_tokens, &WebcashTokenKind::Public, 4).is_err());
        assert!(parse_webcash_tokens(&valid_mixed_tokens, &WebcashTokenKind::Secret, 4).is_err());
        assert!(parse_webcash_tokens(&valid_mixed_tokens, &WebcashTokenKind::Public, 3).is_err());
        assert!(parse_webcash_tokens(&valid_mixed_tokens, &WebcashTokenKind::Secret, 3).is_err());

        let valid_secret_tokens_precision = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1.0000:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert!(
            parse_webcash_tokens(&valid_secret_tokens_precision, &WebcashTokenKind::Public, 4)
                .is_err()
        );
        assert!(
            parse_webcash_tokens(&valid_secret_tokens_precision, &WebcashTokenKind::Secret, 4)
                .is_ok()
        );
        assert!(
            parse_webcash_tokens(&valid_secret_tokens_precision, &WebcashTokenKind::Public, 3)
                .is_err()
        );
        assert!(
            parse_webcash_tokens(&valid_secret_tokens_precision, &WebcashTokenKind::Secret, 3)
                .is_err()
        );

        let total_amount_too_large_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e210000000000:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
        ];
        assert!(parse_webcash_tokens(
            &total_amount_too_large_tokens,
            &WebcashTokenKind::Public,
            100
        )
        .is_err());

        let zero_tokens: Vec<String> = vec![];
        assert!(parse_webcash_tokens(&zero_tokens, &WebcashTokenKind::Public, 100).is_err());

        let invalid_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
            String::from("e210000000000.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
         ];
        assert!(parse_webcash_tokens(&invalid_tokens, &WebcashTokenKind::Public, 100).is_err());
        assert!(parse_webcash_tokens(&invalid_tokens, &WebcashTokenKind::Secret, 100).is_err());

        let duplicate_hex_1 = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
        ];
        assert!(parse_webcash_tokens(&duplicate_hex_1, &WebcashTokenKind::Public, 100).is_err());
        assert!(parse_webcash_tokens(&duplicate_hex_1, &WebcashTokenKind::Secret, 100).is_err());

        let duplicate_hex_2 = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert!(parse_webcash_tokens(&duplicate_hex_2, &WebcashTokenKind::Public, 100).is_err());
        assert!(parse_webcash_tokens(&duplicate_hex_2, &WebcashTokenKind::Secret, 100).is_err());

        let duplicate_hex_3 = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert!(parse_webcash_tokens(&duplicate_hex_3, &WebcashTokenKind::Public, 100).is_err());
        assert!(parse_webcash_tokens(&duplicate_hex_3, &WebcashTokenKind::Secret, 100).is_err());
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
        assert!(is_webcash_amount(decimal("0.00000001")));
        assert!(is_webcash_amount(decimal("1")));
        assert!(is_webcash_amount(decimal("1.00000001")));
        assert!(is_webcash_amount(decimal("209999999999.99999999")));
        assert!(is_webcash_amount(decimal("210000000000")));

        assert!(!is_webcash_amount(decimal("0")));
        assert!(!is_webcash_amount(decimal("0.000000001")));
        assert!(!is_webcash_amount(decimal("1.000000001")));
        assert!(!is_webcash_amount(decimal("209999999999.999999989")));
        assert!(!is_webcash_amount(decimal("210000000000.00000001")));
        assert!(!is_webcash_amount(decimal("210000000000.1")));
        assert!(!is_webcash_amount(decimal("210000000001")));
        assert!(!is_webcash_amount(decimal("-0")));
        assert!(!is_webcash_amount(decimal("-1")));
        assert!(!is_webcash_amount(decimal("-1.1")));
        assert!(!is_webcash_amount(decimal("-210000000000")));
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

    #[test]
    fn test_webcash_token_to_string() {
        let tokens: Vec<&str> = vec![
            "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcde",
            "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde",
            "e1:public:12345678901234567890123456789012345678901234567890123456789abcde",
            "e1:secret:12345678901234567890123456789012345678901234567890123456789abcde",
            "e210000000000.00000000:public:12345678901234567890123456789012345678901234567890123456789abcde",
            "e210000000000.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ];
        for token_string in tokens {
            let token = parse_webcash_token(token_string).unwrap();
            assert!(is_webcash_token(&webcash_token_to_string(&token)));
            assert!(is_webcash_token(&format!("{}", &token)));
            assert_eq!(webcash_token_to_string(&token), format!("{}", &token));
            if token.token_kind == WebcashTokenKind::Secret {
                let public_token = token.to_public();
                assert_eq!(token.amount, public_token.amount);
                assert_ne!(token.token_kind, public_token.token_kind);
                assert_ne!(token.hex_string, public_token.hex_string);
            }
        }
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
            "e1:something:12345678901234567890123456789012345678901234567890123456789abcde"
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

    #[test]
    fn test_epoch() {
        assert_eq!(epoch(1), 0);
        assert_eq!(epoch(525_000), 0);
        assert_eq!(epoch(525_001), 1);
        assert_eq!(epoch(1_069_492), 2);
    }

    #[test]
    fn test_mining_amount_per_mining_report_in_epoch() {
        assert_eq!(
            mining_amount_per_mining_report_in_epoch(0),
            Decimal::new(MINING_AMOUNT_IN_FIRST_EPOCH, 0)
        );
        assert_eq!(
            mining_amount_per_mining_report_in_epoch(44),
            decimal("0.00000001")
        );
        assert_eq!(
            mining_amount_per_mining_report_in_epoch(45),
            decimal("0.00000001")
        );
        assert_eq!(mining_amount_per_mining_report_in_epoch(46), decimal("0"));
        assert_eq!(mining_amount_per_mining_report_in_epoch(63), decimal("0"));
        assert_eq!(mining_amount_per_mining_report_in_epoch(64), decimal("0"));
        assert_eq!(
            mining_amount_per_mining_report_in_epoch(10_000_000),
            decimal("0")
        );
    }

    #[test]
    fn test_mining_amount_for_mining_report() {
        assert_eq!(mining_amount_for_mining_report(1), decimal("200000"));
        assert_eq!(mining_amount_for_mining_report(2), decimal("200000"));
        assert_eq!(mining_amount_for_mining_report(525_000), decimal("200000"));
        assert_eq!(
            mining_amount_for_mining_report(525_000 + 1),
            decimal("100000")
        );
        assert_eq!(
            mining_amount_for_mining_report(2 * 525_000),
            decimal("100000")
        );
        assert_eq!(
            mining_amount_for_mining_report(2 * 525_000 + 1),
            decimal("50000")
        );
        assert_eq!(
            mining_amount_for_mining_report(3 * 525_000),
            decimal("50000")
        );
        assert_eq!(
            mining_amount_for_mining_report(3 * 525_000 + 1),
            decimal("25000")
        );
        assert_eq!(
            mining_amount_for_mining_report(4 * 525_000),
            decimal("25000")
        );
        assert_eq!(
            mining_amount_for_mining_report(4 * 525_000 + 1),
            decimal("12500")
        );
        assert_eq!(
            mining_amount_for_mining_report(5 * 525_000),
            decimal("12500")
        );
        assert_eq!(
            mining_amount_for_mining_report(5 * 525_000 + 1),
            decimal("6250")
        );
        assert_eq!(
            mining_amount_for_mining_report(6 * 525_000),
            decimal("6250")
        );
        assert_eq!(
            mining_amount_for_mining_report(6 * 525_000 + 1),
            decimal("3125")
        );
        assert_eq!(
            mining_amount_for_mining_report(7 * 525_000),
            decimal("3125")
        );
        assert_eq!(
            mining_amount_for_mining_report(7 * 525_000 + 1),
            decimal("1562.5")
        );
        assert_eq!(
            mining_amount_for_mining_report(8 * 525_000),
            decimal("1562.5")
        );
        assert_eq!(
            mining_amount_for_mining_report(8 * 525_000 + 1),
            decimal("781.25")
        );
        assert_eq!(
            mining_amount_for_mining_report(9 * 525_000),
            decimal("781.25")
        );
        assert_eq!(
            mining_amount_for_mining_report(9 * 525_000 + 1),
            decimal("390.625")
        );
        assert_eq!(
            mining_amount_for_mining_report(10 * 525_000),
            decimal("390.625")
        );
        assert_eq!(
            mining_amount_for_mining_report(10 * 525_000 + 1),
            decimal("195.3125")
        );
        assert_eq!(
            mining_amount_for_mining_report(10 * 525_000),
            decimal("390.625")
        );
        assert_eq!(
            mining_amount_for_mining_report(20 * 525_000),
            decimal("0.38146973")
        );
        assert_eq!(
            mining_amount_for_mining_report(30 * 525_000),
            decimal("0.00037253")
        );
        assert_eq!(
            mining_amount_for_mining_report(40 * 525_000),
            decimal("0.00000036")
        );
        assert_eq!(
            mining_amount_for_mining_report(41 * 525_000),
            decimal("0.00000018")
        );
        assert_eq!(
            mining_amount_for_mining_report(42 * 525_000),
            decimal("0.00000009")
        );
        assert_eq!(
            mining_amount_for_mining_report(43 * 525_000),
            decimal("0.00000005")
        );
        assert_eq!(
            mining_amount_for_mining_report(44 * 525_000),
            decimal("0.00000002")
        );
        assert_eq!(
            mining_amount_for_mining_report(45 * 525_000),
            decimal("0.00000001")
        );
        assert_eq!(
            mining_amount_for_mining_report(46 * 525_000),
            decimal("0.00000001")
        );
        assert_eq!(mining_amount_for_mining_report(47 * 525_000), decimal("0"));
        assert_eq!(mining_amount_for_mining_report(50 * 525_000), decimal("0"));
        assert_eq!(mining_amount_for_mining_report(100 * 525_000), decimal("0"));
        assert_eq!(
            mining_amount_for_mining_report(1000 * 525_000),
            decimal("0")
        );
        assert_eq!(mining_amount_for_mining_report(1_069_352), decimal("50000"));
    }

    #[test]
    fn test_mining_subsidy_amount_for_mining_report() {
        assert_eq!(mining_subsidy_amount_for_mining_report(1), decimal("10000"));
        assert_eq!(
            mining_subsidy_amount_for_mining_report(2 * 525_000),
            decimal("5000.00")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(5 * 525_000),
            decimal("625.00")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(8 * 525_000),
            decimal("78.125")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(10 * 525_000),
            decimal("19.53125")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(20 * 525_000),
            decimal("0.01907349")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(30 * 525_000),
            decimal("0.00001863")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(40 * 525_000),
            decimal("0.00000002")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(41 * 525_000),
            decimal("0.00000001")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(42 * 525_000),
            decimal("0")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(100 * 525_000),
            decimal("0")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(1000 * 525_000),
            decimal("0")
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(1_069_352),
            decimal("2500")
        );
    }

    #[test]
    fn test_total_circulation() {
        assert_eq!(total_circulation(1), decimal("200000"));
        assert_eq!(total_circulation(10), decimal("2000000"));
        assert_eq!(total_circulation(100), decimal("20000000"));
        assert_eq!(total_circulation(1000), decimal("200000000"));
        assert_eq!(total_circulation(10000), decimal("2000000000"));
        assert_eq!(total_circulation(100_000), decimal("20000000000"));
        assert_eq!(total_circulation(1_000_000), decimal("152500000000"));
        assert_eq!(
            total_circulation(10_000_000),
            decimal("209999608993.52675000")
        );
        assert_eq!(
            total_circulation(100_000_000),
            decimal("209999999999.99475000")
        );
        assert_eq!(
            total_circulation(1_000_000_000),
            decimal("209999999999.99475000")
        );

        assert_eq!(total_circulation(524_999), decimal("104999800000"));
        assert_eq!(total_circulation(525_000), decimal("105000000000"));
        assert_eq!(total_circulation(525_001), decimal("105000100000"));
    }

    #[test]
    fn test_find_max_supply() {
        let mut epoch = 0;
        let first_zero_reward_epoch;
        loop {
            let reward_in_epoch = mining_amount_per_mining_report_in_epoch(epoch);
            if reward_in_epoch == decimal("0") {
                first_zero_reward_epoch = epoch;
                break;
            }
            epoch += 1;
        }
        assert_eq!(first_zero_reward_epoch, 46);
        assert_eq!(
            mining_amount_per_mining_report_in_epoch(first_zero_reward_epoch),
            decimal("0")
        );
        assert_ne!(
            total_circulation(first_zero_reward_epoch * MINING_REPORTS_PER_EPOCH - 1),
            total_circulation(first_zero_reward_epoch * MINING_REPORTS_PER_EPOCH)
        );
        assert_eq!(
            total_circulation(first_zero_reward_epoch * MINING_REPORTS_PER_EPOCH),
            total_circulation(first_zero_reward_epoch * MINING_REPORTS_PER_EPOCH + 1)
        );
        assert_eq!(
            total_circulation(first_zero_reward_epoch * MINING_REPORTS_PER_EPOCH),
            decimal("209999999999.99475000")
        );
    }

    #[test]
    fn test_total_mining_amount() {
        let mut total_mining_amount = Decimal::default();
        for epoch in 0..=100 {
            let per_mining_report_mining_amount = mining_amount_per_mining_report_in_epoch(epoch);
            total_mining_amount += per_mining_report_mining_amount
                * Decimal::new(i64::from(MINING_REPORTS_PER_EPOCH), 0);
        }
        assert_eq!(total_mining_amount, decimal("209999999999.99475000"));
        assert_eq!(total_mining_amount, total_circulation(4_294_967_295));
        let missing_webcash = Decimal::new(MAX_WEBCASH, 0) - total_mining_amount;
        assert_eq!(missing_webcash, decimal("0.00525000"));
    }
}
