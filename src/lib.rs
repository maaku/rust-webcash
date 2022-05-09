use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const OPTIONAL_AMOUNT_PREFIX: &str = "e";
const MAX_WEBCASH: i64 = 210_000_000_000;
const WEBCASH_DECIMALS: u32 = 8;

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

impl WebcashEconomy {
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
        self.public_hash_to_amount_state
            .values()
            .filter(|amount_state| !amount_state.spent)
            .map(|amount_state| amount_state.amount)
            .sum::<Decimal>()
            .normalize()
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

    fn print(&self) {
        let mut total_unspent: Decimal = Decimal::new(0, 0);
        for (public_hash, amount_state) in &self.public_hash_to_amount_state {
            let amount = amount_state.amount;
            let spent = amount_state.spent;
            if !spent {
                println!("public_hash={public_hash} amount={amount}");
                total_unspent += amount;
            }
        }
        assert_eq!(total_unspent, self.get_total_unspent());
        println!("Total unspent: {}", total_unspent.normalize());
        println!();
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
        self.print();
        if self.persist_to_disk {
            self.sync_to_disk();
        }
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
        let temporary_filename = format!("{}.{}", WEBCASH_ECONOMY_JSON_FILE, std::process::id());
        let file = File::create(&temporary_filename).unwrap();
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, self).unwrap();
        std::fs::rename(temporary_filename, WEBCASH_ECONOMY_JSON_FILE).unwrap();
    }

    fn mark_as_spent(&mut self, secret_webcash_token: &WebcashToken) {
        assert_eq!(secret_webcash_token.token_kind, WebcashTokenKind::Secret);
        assert!(self.is_unspent_secret_token_with_correct_amount(secret_webcash_token));
        let amount_state: &mut AmountState = self
            .public_hash_to_amount_state
            .get_mut(&secret_webcash_token.to_public().hex_string)
            .unwrap();
        assert!(!amount_state.spent);
        amount_state.spent = true;
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
        self.print();
        true
    }
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
}
