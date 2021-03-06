// Copyright (c) 2022 Webcash Developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use thousands::Separable;
#[macro_use]
extern crate log;
use primitive_types::H256;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

const OPTIONAL_AMOUNT_PREFIX: &str = "e";
const HEX_STRING_LENGTH: usize = 64;
// It is a bit unfortunate, but the total issuance of webcash slightly exceeds
// the representable range of a 64-bit integer.  We still use u64 to represent
// amounts as no user transaction will ever have to exceed the implied limit of
// 2^64 webcash per output.  But this does mean that calculations of the total
// issuance need to use u128 instead of webcash amounts.
pub const MAX_WEBCASH: u64 = 92_233_720_368__5477_5807; // 2^64 - 1
pub const TOTAL_ISSUANCE: u128 = 209_999_999_999__9265_0000;
pub const WEBCASH_DECIMALS: u32 = 8;

const MINING_AMOUNT_IN_FIRST_EPOCH: u64 = 200_000__0000_0000;
const MINING_REPORTS_PER_EPOCH: usize = 525_000;
const MINING_SOLUTION_MAX_AGE_IN_SECONDS: u64 = 2 * 60 * 60; // 2 hrs
const MINING_SUBSIDY_FRAC_NUMERATOR: u64 = 1; // 1/20 = 0.05
const MINING_SUBSIDY_FRAC_DENOMINATOR: u64 = 20;

const WEBCASH_KIND_IDENTIFIER_SECRET: &str = "secret";
const WEBCASH_KIND_IDENTIFIER_PUBLIC: &str = "public";

const WEBCASH_ECONOMY_JSON_FILE: &str = "webcashd.json";

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Amount {
    pub value: u64,
}

impl Serialize for Amount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        std::str::FromStr::from_str(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl std::ops::Add for Amount {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        Amount::from(self.value + other.value)
    }
}

impl std::ops::Sub for Amount {
    type Output = Self;
    fn sub(self, other: Self) -> Self::Output {
        Amount::from(self.value - other.value)
    }
}

impl std::iter::Sum for Amount {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        Self::from(iter.map(|wc| wc.value).sum::<u64>())
    }
}

impl std::convert::From<u64> for Amount {
    fn from(n: u64) -> Self {
        // Disabling this check for now, as the server is currently written in
        // such a way that Amounts are often initialized with zero.  Indedd in
        // many contexts this makes sense to do (e.g. initializing a sum
        // accumulator).  We shoudl assess whether implementing this constraint
        // is worth it.
        // assert!(1 <= n);
        assert!(n <= MAX_WEBCASH);
        Amount { value: n }
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let divmod = (
            self.value / 10_u64.pow(WEBCASH_DECIMALS),
            self.value % 10_u64.pow(WEBCASH_DECIMALS),
        );
        if divmod.1 == 0 {
            // Integer number of webcash, so don't use a decimal point.
            write!(fmt, "{}", divmod.0)
        } else {
            // Add leading zeros
            // Note: This should be using the WEBCASH_DECIMALS constant here,
            //       but I'm not sure how to convert that to a string such that
            //       the format!() macro can use it.
            let mut frac = format!("{:08}", divmod.1);
            // Remove trailing zeros
            while let Some(c) = frac.pop() {
                if c != '0' {
                    frac.push(c);
                    break;
                }
            }
            // Combine integer and fractional parts
            write!(fmt, "{}.{}", divmod.0, frac)
        }
    }
}

impl std::str::FromStr for Amount {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Amount, Self::Err> {
        // Remove optional amount prefix
        let s = if !OPTIONAL_AMOUNT_PREFIX.is_empty() && s.starts_with(OPTIONAL_AMOUNT_PREFIX) {
            &s[OPTIONAL_AMOUNT_PREFIX.len()..]
        } else {
            s
        };
        // Make sure we're dealing with an integer or fraction only
        if !s.chars().all(|ch| ('0'..='9').contains(&ch) || ch == '.') {
            return Err("amount string contains unexpected characters")?;
        }
        // Make sure there's no unnecessary leading zeros
        if s.starts_with('0') && !s.starts_with("0.") {
            return Err("unnecessary leading zeros are disallowed")?;
        }
        if s.contains('.') {
            // Validate integer part
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() != 2 {
                return Err("amount string contains unexpected characters")?;
            }
            let int_part = parts[0]
                .parse::<u64>()?
                .checked_mul(10_u64.pow(WEBCASH_DECIMALS));
            if int_part.is_none() {
                return Err("overflow")?;
            }
            // Validate fractional part
            if WEBCASH_DECIMALS < (parts[1].len() as u32) {
                return Err("too many fractional digits")?;
            }
            let frac_part = parts[1]
                .parse::<u64>()?
                .checked_mul(10_u64.pow(WEBCASH_DECIMALS - (parts[1].len() as u32)));
            if frac_part.is_none() {
                return Err("overflow")?;
            }
            // Combine both parts
            let n = int_part.unwrap().checked_add(frac_part.unwrap());
            if n.is_none() {
                return Err("overflow")?;
            }
            let n = n.unwrap();
            if n < 1 {
                return Err("underflow")?;
            }
            if n > MAX_WEBCASH {
                return Err("overflow")?;
            }
            Ok(Amount::from(n))
        } else {
            // Parse and scale string as integer part only
            let n = s.parse::<u64>()?.checked_mul(10_u64.pow(WEBCASH_DECIMALS));
            if n.is_none() {
                return Err("overflow")?;
            }
            let n = n.unwrap();
            if n < 1 {
                return Err("underflow")?;
            }
            if n > MAX_WEBCASH {
                return Err("overflow")?;
            }
            Ok(Amount::from(n))
        }
    }
}

#[derive(PartialEq)]
pub enum WebcashKind {
    Secret,
    Public,
}

impl std::fmt::Display for WebcashKind {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WebcashKind::Secret => write!(fmt, "{}", WEBCASH_KIND_IDENTIFIER_SECRET),
            WebcashKind::Public => write!(fmt, "{}", WEBCASH_KIND_IDENTIFIER_PUBLIC),
        }
    }
}

impl std::str::FromStr for WebcashKind {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<WebcashKind, Self::Err> {
        match s {
            WEBCASH_KIND_IDENTIFIER_SECRET => Ok(WebcashKind::Secret),
            WEBCASH_KIND_IDENTIFIER_PUBLIC => Ok(WebcashKind::Public),
            _ => Err("unexpected webcash claim code type")?,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecretWebcash {
    pub secret: String,
    pub amount: Amount,
}

impl Serialize for SecretWebcash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretWebcash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        std::str::FromStr::from_str(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl std::fmt::Display for SecretWebcash {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            fmt,
            "{}{}:{}:{}",
            OPTIONAL_AMOUNT_PREFIX,
            self.amount,
            WebcashKind::Secret,
            self.secret,
        )?;
        Ok(())
    }
}

impl std::str::FromStr for SecretWebcash {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<SecretWebcash, Self::Err> {
        // Split the input into amount, kind, secret
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 3 {
            return Err("insufficient number of segments in webcash code")?;
        }
        // Parse and validate each component
        let amount: Amount = parts[0].parse()?;
        let kind: WebcashKind = parts[1].parse()?;
        let secret: String = parts[2..].join(":");
        // Only accept SecretWebcash
        if kind != WebcashKind::Secret {
            return Err("expected secret webcash code")?;
        }
        Ok(SecretWebcash { secret, amount })
    }
}

#[derive(PartialEq, Debug)]
pub struct PublicWebcash {
    pub hash: H256,
    pub amount: Option<Amount>,
}

impl Serialize for PublicWebcash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PublicWebcash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        std::str::FromStr::from_str(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl SecretWebcash {
    #[must_use]
    fn to_public(&self) -> PublicWebcash {
        PublicWebcash {
            hash: H256::from_slice(&Sha256::digest(&self.secret)),
            amount: Some(self.amount),
        }
    }
}

impl std::fmt::Display for PublicWebcash {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            fmt,
            "{}{}:{}:{:x}",
            OPTIONAL_AMOUNT_PREFIX,
            self.amount.map_or("0".to_owned(), |n| n.to_string()),
            WebcashKind::Public,
            self.hash,
        )?;
        Ok(())
    }
}

fn is_webcash_hex_string(hex: &str) -> bool {
    hex.len() == HEX_STRING_LENGTH
        && hex.chars().all(|ch| {
            ('0'..='9').contains(&ch) || ('a'..='f').contains(&ch) || ('A'..='F').contains(&ch)
        })
}

impl std::str::FromStr for PublicWebcash {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split the input into amount, kind, hash
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err("unexpected number of segments in webcash code")?;
        }
        // Parse and validate each component
        let amount: Option<Amount> = parts[0].parse().ok();
        let kind: WebcashKind = parts[1].parse()?;
        // Note: The primitive-types crate does full validation of input for
        //       hash values, ensuring that it is a 64-character hex-encoded
        //       string.  To protect against regressions, we should check that
        //       other strings are rejected in our own module's unit tests.
        if !is_webcash_hex_string(parts[2]) {
            return Err("public webcash code must be 64-character hex string")?;
        }
        let hash: H256 = parts[2].parse()?;
        // Only accept PublicWebcash
        if kind != WebcashKind::Public {
            return Err("expected public webcash code")?;
        }
        Ok(PublicWebcash { hash, amount })
    }
}

pub trait CheckForDuplicates {
    fn contains_duplicates(&self) -> bool;
}

impl CheckForDuplicates for Vec<SecretWebcash> {
    #[must_use]
    fn contains_duplicates(&self) -> bool {
        let mut unique_hex_strings: Vec<String> = self.iter().map(|wc| wc.secret.clone()).collect(); // FIXME: can we remove this .clone()?
        unique_hex_strings.sort();
        unique_hex_strings.dedup();
        unique_hex_strings.len() != self.len()
    }
}

impl CheckForDuplicates for Vec<PublicWebcash> {
    #[must_use]
    fn contains_duplicates(&self) -> bool {
        let mut unique_hashes: Vec<H256> = self.iter().map(|wc| wc.hash).collect();
        unique_hashes.sort();
        unique_hashes.dedup();
        unique_hashes.len() != self.len()
    }
}

pub trait SumAmounts {
    fn total_value(&self) -> Option<Amount>;
}

impl SumAmounts for Vec<SecretWebcash> {
    #[must_use]
    fn total_value(&self) -> Option<Amount> {
        if self.is_empty() {
            None
        } else {
            Some(self.iter().map(|wc| wc.amount).sum())
        }
    }
}

impl SumAmounts for Vec<PublicWebcash> {
    #[must_use]
    fn total_value(&self) -> Option<Amount> {
        self.iter().map(|wc| wc.amount).sum()
    }
}

#[derive(Deserialize, Serialize)]
pub struct Output {
    pub amount: Amount,
    pub spent: bool,
}

// https://github.com/serde-rs/serde/issues/368
fn serde_default_literals_workaround_default_true() -> bool {
    true
}

#[derive(Deserialize, Serialize)]
pub struct WebcashEconomy {
    public_hash_to_amount_state: std::collections::HashMap<H256, Output>,
    #[serde(skip, default = "serde_default_literals_workaround_default_true")]
    persist_to_disk: bool,
}

const DUMMY_VALUE_MINING_REPORTS: usize = 1_000_000;
const DUMMY_VALUE_DIFFICULTY_TARGET_BITS: u8 = 20;
const DUMMY_VALUE_RATIO: f32 = 1.0001;

impl WebcashEconomy {
    #[must_use]
    pub fn get_epoch(&self) -> usize {
        epoch(self.get_mining_reports())
    }

    #[must_use]
    pub fn get_total_circulation(&self) -> u128 {
        total_circulation(self.get_mining_reports())
    }

    #[must_use]
    pub fn get_mining_amount(&self) -> Amount {
        Amount::from(mining_amount_for_mining_report(self.get_mining_reports()))
    }

    #[must_use]
    pub fn get_subsidy_amount(&self) -> Amount {
        Amount::from(mining_subsidy_amount_for_mining_report(
            self.get_mining_reports(),
        ))
    }

    #[must_use]
    pub fn get_mining_reports(&self) -> usize {
        DUMMY_VALUE_MINING_REPORTS
    }

    #[must_use]
    pub fn get_difficulty_target_bits(&self) -> u8 {
        DUMMY_VALUE_DIFFICULTY_TARGET_BITS
    }

    #[must_use]
    pub fn get_ratio(&self) -> f32 {
        DUMMY_VALUE_RATIO
    }

    #[must_use]
    pub fn new(persist_to_disk: bool) -> WebcashEconomy {
        let mut webcash_economy = WebcashEconomy {
            public_hash_to_amount_state: std::collections::HashMap::default(),
            persist_to_disk,
        };
        if webcash_economy.persist_to_disk {
            webcash_economy.read_from_disk();
            webcash_economy.sync_to_disk();
        }
        webcash_economy
    }

    #[must_use]
    pub fn is_valid_proof_of_work(&self, preimage: &str, preimage_timestamp: i64) -> bool {
        let timestamp_diff = (chrono::Utc::now().timestamp() - preimage_timestamp).unsigned_abs();
        if timestamp_diff > MINING_SOLUTION_MAX_AGE_IN_SECONDS {
            return false;
        }
        let preimage_hash = Sha256::digest(preimage);
        let preimage_hash_as_u256 = primitive_types::U256::from_big_endian(&preimage_hash);
        preimage_hash_as_u256.leading_zeros() >= u32::from(self.get_difficulty_target_bits())
    }

    #[must_use]
    pub fn get_total_unspent(&self) -> Amount {
        let now = std::time::Instant::now();
        let total_unspent = self
            .public_hash_to_amount_state
            .values()
            .filter(|amount_state| !amount_state.spent)
            .map(|amount_state| amount_state.amount)
            .sum::<Amount>();
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
            "Calculating number of unspent tokens took {} ms.",
            now.elapsed().as_millis()
        );
        number_of_unspent_tokens
    }

    #[must_use]
    pub fn get_using_public_token(&self, public_token: &PublicWebcash) -> Option<&Output> {
        self.public_hash_to_amount_state.get(&public_token.hash)
    }

    #[must_use]
    fn get_using_secret_token(&self, secret_token: &SecretWebcash) -> Option<&Output> {
        self.get_using_public_token(&secret_token.to_public())
    }

    #[must_use]
    fn is_unspent_secret_token_with_correct_amount(&self, secret_token: &SecretWebcash) -> bool {
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
    fn are_unspent_valid_input_tokens(&self, secret_input_tokens: &[SecretWebcash]) -> bool {
        if !secret_input_tokens
            .iter()
            .all(|wc| self.is_unspent_secret_token_with_correct_amount(wc))
        {
            return false;
        }
        true
    }

    #[must_use]
    fn is_valid_output_token_with_non_taken_hash(&self, secret_token: &SecretWebcash) -> bool {
        self.get_using_secret_token(secret_token).is_none()
    }

    #[must_use]
    fn are_valid_output_tokens_with_non_taken_hashes(
        &self,
        secret_output_tokens: &[SecretWebcash],
    ) -> bool {
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

    fn create_token(&mut self, secret_webcash_token: &SecretWebcash) {
        let old_value = self.public_hash_to_amount_state.insert(
            secret_webcash_token.to_public().hash,
            Output {
                amount: secret_webcash_token.amount,
                spent: false,
            },
        );
        assert!(old_value.is_none()); // FIXME: should check before insertion?
        debug!(
            "[diff: +] Token of amount {} created",
            secret_webcash_token.amount.separate_with_commas()
        );
    }

    #[must_use]
    pub fn create_tokens(&mut self, secret_outputs: &Vec<SecretWebcash>) -> bool {
        let total_unspent_before = self.get_total_unspent();
        if !self.are_valid_output_tokens_with_non_taken_hashes(secret_outputs) {
            return false;
        }
        for secret_output in secret_outputs {
            self.create_token(secret_output);
        }
        assert_eq!(
            // FIXME: Should be checked before?
            Some(self.get_total_unspent() - total_unspent_before),
            secret_outputs.total_value()
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
        let file = std::fs::File::open(WEBCASH_ECONOMY_JSON_FILE).unwrap();
        let reader = std::io::BufReader::new(file);
        let webcash_economy: WebcashEconomy = serde_json::from_reader(reader).unwrap();
        *self = webcash_economy;
    }

    fn sync_to_disk(&self) {
        assert!(self.persist_to_disk);
        let now = std::time::Instant::now();
        let temporary_filename = format!("{}.{}", WEBCASH_ECONOMY_JSON_FILE, std::process::id());
        let file = std::fs::File::create(&temporary_filename).unwrap();
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer(writer, self).unwrap();
        std::fs::rename(temporary_filename, WEBCASH_ECONOMY_JSON_FILE).unwrap();
        trace!("Sync to disk took {} ms.", now.elapsed().as_millis());
    }

    fn mark_as_spent(&mut self, secret_webcash_token: &SecretWebcash) {
        assert!(self.is_unspent_secret_token_with_correct_amount(secret_webcash_token));
        let amount_state: &mut Output = self
            .public_hash_to_amount_state
            .get_mut(&secret_webcash_token.to_public().hash)
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
        secret_inputs: &Vec<SecretWebcash>,
        secret_outputs: &Vec<SecretWebcash>,
    ) -> bool {
        let total_unspent_before = self.get_total_unspent();
        if !self.are_unspent_valid_input_tokens(secret_inputs) {
            return false;
        }
        if !self.are_valid_output_tokens_with_non_taken_hashes(secret_outputs) {
            return false;
        }
        if [secret_inputs.as_slice(), secret_outputs.as_slice()]
            .concat()
            .contains_duplicates()
        {
            return false;
        }
        if secret_inputs.total_value() != secret_outputs.total_value() {
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
fn mining_amount_per_mining_report_in_epoch(epoch: usize) -> u64 {
    if epoch >= 64 {
        0
    } else {
        MINING_AMOUNT_IN_FIRST_EPOCH >> epoch
    }
}

// TODO: How to handle zero return value case (in the future when no mining reward))? Is not a valid webcash amount.
#[must_use]
fn mining_amount_for_mining_report(num_mining_reports: usize) -> u64 {
    mining_amount_per_mining_report_in_epoch(epoch(num_mining_reports))
}

// TODO: How to handle zero return value case? Is not a valid webcash amount.
#[must_use]
fn mining_subsidy_amount_for_mining_report(num_mining_reports: usize) -> u64 {
    mining_amount_per_mining_report_in_epoch(epoch(num_mining_reports))
        * MINING_SUBSIDY_FRAC_NUMERATOR
        / MINING_SUBSIDY_FRAC_DENOMINATOR
}

#[must_use]
fn epoch(num_mining_reports: usize) -> usize {
    num_mining_reports / MINING_REPORTS_PER_EPOCH
}

#[must_use]
fn total_circulation(num_mining_reports: usize) -> u128 {
    let mut total_circulation: u128 = 0;
    let mut mining_reports_in_current_epoch = num_mining_reports;
    for past_epoch in 0..epoch(num_mining_reports) {
        total_circulation += u128::from(
            mining_amount_per_mining_report_in_epoch(past_epoch) * MINING_REPORTS_PER_EPOCH as u64,
        );
        mining_reports_in_current_epoch -= MINING_REPORTS_PER_EPOCH;
    }
    total_circulation
        + u128::from(
            mining_amount_per_mining_report_in_epoch(epoch(num_mining_reports))
                * mining_reports_in_current_epoch as u64,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_to_public() {
        assert_eq!(
            "e1:secret:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                .parse::<SecretWebcash>()
                .unwrap()
                .to_public()
                .to_string(),
            "e1:public:d7914fe546b684688bb95f4f888a92dfc680603a75f23eb823658031fff766d9"
        );
        assert_eq!(
            "e1:secret:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
                .parse::<SecretWebcash>()
                .unwrap()
                .to_public()
                .to_string(),
            "e1:public:049da052634feb56ce6ec0bc648c672011edff1cb272b53113bbc90a8f00249c"
        );
    }

    fn parse_secret_webcash(v: &[String]) -> Vec<SecretWebcash> {
        v.iter()
            .map(|s| s.parse::<SecretWebcash>())
            .filter(std::result::Result::is_ok)
            .map(std::result::Result::unwrap)
            .collect()
    }

    fn parse_public_webcash(v: &[String]) -> Vec<PublicWebcash> {
        v.iter()
            .map(|s| s.parse::<PublicWebcash>())
            .filter(std::result::Result::is_ok)
            .map(std::result::Result::unwrap)
            .collect()
    }

    #[test]
    fn test_parse_webcash_tokens() {
        let valid_secret_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert_eq!(parse_secret_webcash(&valid_secret_tokens).len(), 4);
        assert_eq!(parse_public_webcash(&valid_secret_tokens).len(), 0);

        let valid_public_tokens = vec![
            String::from("e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:public:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:public:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert_eq!(parse_secret_webcash(&valid_public_tokens).len(), 0);
        assert_eq!(parse_public_webcash(&valid_public_tokens).len(), 4);

        let valid_mixed_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:public:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert_eq!(parse_secret_webcash(&valid_mixed_tokens).len(), 3);
        assert_eq!(parse_public_webcash(&valid_mixed_tokens).len(), 1);

        let valid_secret_tokens_precision = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1.00000000:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1.0000:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert_eq!(
            parse_secret_webcash(&valid_secret_tokens_precision).len(),
            4
        );
        assert_eq!(
            parse_public_webcash(&valid_secret_tokens_precision).len(),
            0
        );

        let total_amount_too_large_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e210000000000:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
        ];
        assert_eq!(
            parse_secret_webcash(&total_amount_too_large_tokens).len(),
            1
        );

        let invalid_tokens = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
            String::from("e92233720368.54775808:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
        ];
        assert_eq!(parse_secret_webcash(&invalid_tokens).len(), 3);

        let duplicate_hex_1 = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd2"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
        ];
        assert_eq!(parse_secret_webcash(&duplicate_hex_1).len(), 4);
        assert!(parse_secret_webcash(&duplicate_hex_1).contains_duplicates());

        let duplicate_hex_2 = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert_eq!(parse_secret_webcash(&duplicate_hex_2).len(), 4);
        assert_eq!(
            parse_secret_webcash(&duplicate_hex_2).contains_duplicates(),
            true
        );

        let duplicate_hex_3 = vec![
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcd1"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd3"),
            String::from("e1:secret:12345678901234567890123456789012345678901234567890123456789abcd4"),
        ];
        assert_eq!(parse_secret_webcash(&duplicate_hex_3).len(), 4);
        assert!(parse_secret_webcash(&duplicate_hex_3).contains_duplicates());
    }

    fn is_webcash_amount(s: &str) -> bool {
        s.parse::<Amount>().is_ok()
    }

    #[test]
    fn test_decimal_from_str() {
        assert!(!is_webcash_amount("Inf"));
        assert!(!is_webcash_amount("-Inf"));
        assert!(!is_webcash_amount("NaN"));
        assert!(!is_webcash_amount("-NaN"));
    }

    #[test]
    fn test_is_webcash_amount() {
        assert!(is_webcash_amount("0.00000001"));
        assert!(is_webcash_amount("1"));
        assert!(is_webcash_amount("1.00000001"));
        assert!(is_webcash_amount("92233720368.54775807"));
        assert!(is_webcash_amount("92233720368"));

        assert!(!is_webcash_amount("0"));
        assert!(!is_webcash_amount("0.000000001"));
        assert!(!is_webcash_amount("1.000000001"));
        assert!(!is_webcash_amount("92233720368.547758069"));
        assert!(!is_webcash_amount("92233720368.54775808"));
        assert!(!is_webcash_amount("92233720368.6"));
        assert!(!is_webcash_amount("92233720369"));
        assert!(!is_webcash_amount("-0"));
        assert!(!is_webcash_amount("-1"));
        assert!(!is_webcash_amount("-1.1"));
        assert!(!is_webcash_amount("-92233720368"));
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
    fn test_is_public_webcash() {
        assert!(is_public_webcash(
            "e1:public:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(is_public_webcash(
            "e1:public:0ba1c936042f2d6aade5563e9fb319275aec0ee6a262a5a77be01aad99a98cf2"
        ));

        assert!(!is_public_webcash("e1:public:"));
        assert!(!is_public_webcash("e1:public:0"));
        assert!(!is_public_webcash("e1:public:01"));
        assert!(!is_public_webcash(
            "e1:public:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
        ));
        assert!(!is_public_webcash(
            "e1:public: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_public_webcash(
            "e1:public:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
        ));
        assert!(!is_public_webcash(
            "e1:public:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
        ));
        assert!(!is_public_webcash(
            "e1:public:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde "
        ));
        assert!(!is_public_webcash(
            "e1:public:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
        ));
    }

    #[test]
    fn test_webcash_token_to_string() {
        let tokens: Vec<&str> = vec![
            "e0.00000001:public:12345678901234567890123456789012345678901234567890123456789abcde",
            "e0.00000001:secret:12345678901234567890123456789012345678901234567890123456789abcde",
            "e1:public:12345678901234567890123456789012345678901234567890123456789abcde",
            "e1:secret:12345678901234567890123456789012345678901234567890123456789abcde",
            "e92233720368.54775807:public:12345678901234567890123456789012345678901234567890123456789abcde",
            "e92233720368.54775807:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ];
        for token_string in tokens {
            let secret = token_string.parse::<SecretWebcash>();
            let public = token_string.parse::<PublicWebcash>();
            assert!(secret.is_ok() || public.is_ok());
            if let Ok(secret) = secret {
                assert_eq!(secret, secret.to_string().parse::<SecretWebcash>().unwrap());
                assert_eq!(secret.to_string(), format!("{}", &secret));
                let public = secret.to_public();
                assert!(public.amount.is_some());
                assert_eq!(public.amount.unwrap(), secret.amount);
                assert_eq!(
                    public.hash,
                    H256::from_slice(&Sha256::digest(&secret.secret))
                );
            }
            if let Ok(public) = public {
                assert_eq!(public, public.to_string().parse::<PublicWebcash>().unwrap());
                assert_eq!(public.to_string(), format!("{}", &public));
            }
        }
    }

    fn is_public_webcash(s: &str) -> bool {
        s.parse::<PublicWebcash>().is_ok()
    }

    fn is_secret_webcash(s: &str) -> bool {
        s.parse::<SecretWebcash>().is_ok()
    }

    fn is_webcash_token(s: &str) -> bool {
        is_public_webcash(s) || is_secret_webcash(s)
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
            "e92233720368:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
        assert!(is_webcash_token(
            "e92233720368.5477:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
        assert!(is_webcash_token(
            "e92233720368.54775807:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
        assert!(is_webcash_token("e1:secret::"));
        assert!(is_webcash_token(
            "1:secret:12345678901234567890123456789012345678901234567890123456789abcde "
        ));
        assert!(is_webcash_token(
            "1:secret:12345678901234567890123456789012345678901234567890123456789abcde:"
        ));

        assert!(!is_webcash_token(""));
        assert!(!is_webcash_token("::"));
        assert!(!is_webcash_token(":::"));
        assert!(!is_webcash_token("e:::"));
        assert!(!is_webcash_token("e1:::"));
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
            "e92233720368.547758070:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
        assert!(!is_webcash_token(
            "e92233720368.54775808:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
        assert!(!is_webcash_token(
            "e922337203685.4775807:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
        assert!(!is_webcash_token(
            "e922337203685477.5807:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
        assert!(!is_webcash_token(
            "e9223372036854775807:secret:12345678901234567890123456789012345678901234567890123456789abcde"
        ));
    }

    #[test]
    fn test_epoch() {
        assert_eq!(epoch(1), 0);
        assert_eq!(epoch(524_999), 0);
        assert_eq!(epoch(525_000), 1);
        assert_eq!(epoch(1_069_492), 2);
    }

    #[test]
    fn test_mining_amount_per_mining_report_in_epoch() {
        assert_eq!(
            mining_amount_per_mining_report_in_epoch(0),
            MINING_AMOUNT_IN_FIRST_EPOCH
        );
        assert_eq!(mining_amount_per_mining_report_in_epoch(43), 2);
        assert_eq!(mining_amount_per_mining_report_in_epoch(44), 1);
        assert_eq!(mining_amount_per_mining_report_in_epoch(45), 0);
        assert_eq!(mining_amount_per_mining_report_in_epoch(63), 0);
        assert_eq!(mining_amount_per_mining_report_in_epoch(64), 0);
        assert_eq!(mining_amount_per_mining_report_in_epoch(10_000_000), 0);
    }

    #[test]
    fn test_mining_amount_for_mining_report() {
        assert_eq!(mining_amount_for_mining_report(1), 200000_00000000);
        assert_eq!(mining_amount_for_mining_report(2), 200000_00000000);
        assert_eq!(
            mining_amount_for_mining_report(525_000 - 1),
            200000_00000000
        );
        assert_eq!(mining_amount_for_mining_report(525_000), 100000_00000000);
        assert_eq!(
            mining_amount_for_mining_report(2 * 525_000 - 1),
            100000_00000000
        );
        assert_eq!(mining_amount_for_mining_report(2 * 525_000), 50000_00000000);
        assert_eq!(
            mining_amount_for_mining_report(3 * 525_000 - 1),
            50000_00000000
        );
        assert_eq!(mining_amount_for_mining_report(3 * 525_000), 25000_00000000);
        assert_eq!(
            mining_amount_for_mining_report(4 * 525_000 - 1),
            25000_00000000
        );
        assert_eq!(mining_amount_for_mining_report(4 * 525_000), 12500_00000000);
        assert_eq!(
            mining_amount_for_mining_report(5 * 525_000 - 1),
            12500_00000000
        );
        assert_eq!(mining_amount_for_mining_report(5 * 525_000), 6250_00000000);
        assert_eq!(
            mining_amount_for_mining_report(6 * 525_000 - 1),
            6250_00000000
        );
        assert_eq!(mining_amount_for_mining_report(6 * 525_000), 3125_00000000);
        assert_eq!(
            mining_amount_for_mining_report(7 * 525_000 - 1),
            3125_00000000
        );
        assert_eq!(mining_amount_for_mining_report(7 * 525_000), 1562_50000000);
        assert_eq!(
            mining_amount_for_mining_report(8 * 525_000 - 1),
            1562_50000000
        );
        assert_eq!(mining_amount_for_mining_report(8 * 525_000), 781_25000000);
        assert_eq!(
            mining_amount_for_mining_report(9 * 525_000 - 1),
            781_25000000
        );
        assert_eq!(mining_amount_for_mining_report(9 * 525_000), 390_62500000);
        assert_eq!(
            mining_amount_for_mining_report(10 * 525_000 - 1),
            390_62500000
        );
        assert_eq!(mining_amount_for_mining_report(10 * 525_000), 195_31250000);
        assert_eq!(mining_amount_for_mining_report(20 * 525_000), 19073486);
        assert_eq!(mining_amount_for_mining_report(30 * 525_000), 18626);
        assert_eq!(mining_amount_for_mining_report(40 * 525_000), 18);
        assert_eq!(mining_amount_for_mining_report(41 * 525_000), 9);
        assert_eq!(mining_amount_for_mining_report(42 * 525_000), 4);
        assert_eq!(mining_amount_for_mining_report(43 * 525_000), 2);
        assert_eq!(mining_amount_for_mining_report(44 * 525_000), 1);
        assert_eq!(mining_amount_for_mining_report(45 * 525_000), 0);
        assert_eq!(mining_amount_for_mining_report(50 * 525_000), 0);
        assert_eq!(mining_amount_for_mining_report(100 * 525_000), 0);
        assert_eq!(mining_amount_for_mining_report(1000 * 525_000), 0);
        assert_eq!(mining_amount_for_mining_report(1_069_352), 50000_00000000);
    }

    #[test]
    fn test_mining_subsidy_amount_for_mining_report() {
        assert_eq!(mining_subsidy_amount_for_mining_report(0), 10000_00000000);
        assert_eq!(
            mining_subsidy_amount_for_mining_report(1 * 525_000 - 1),
            10000_00000000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(1 * 525_000),
            5000_00000000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(2 * 525_000 - 1),
            5000_00000000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(2 * 525_000),
            2500_00000000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(5 * 525_000 - 1),
            625_00000000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(5 * 525_000),
            312_50000000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(8 * 525_000 - 1),
            78_12500000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(8 * 525_000),
            39_06250000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(10 * 525_000 - 1),
            19_53125000
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(10 * 525_000),
            9_76562500
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(20 * 525_000 - 1),
            1907348
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(20 * 525_000),
            953674
        );
        assert_eq!(
            mining_subsidy_amount_for_mining_report(30 * 525_000 - 1),
            1862
        );
        assert_eq!(mining_subsidy_amount_for_mining_report(30 * 525_000), 931);
        assert_eq!(mining_subsidy_amount_for_mining_report(39 * 525_000 - 1), 3);
        assert_eq!(mining_subsidy_amount_for_mining_report(39 * 525_000), 1);
        assert_eq!(mining_subsidy_amount_for_mining_report(40 * 525_000 - 1), 1);
        assert_eq!(mining_subsidy_amount_for_mining_report(40 * 525_000), 0);
        assert_eq!(mining_subsidy_amount_for_mining_report(41 * 525_000 - 1), 0);
        assert_eq!(mining_subsidy_amount_for_mining_report(41 * 525_000), 0);
        assert_eq!(mining_subsidy_amount_for_mining_report(100 * 525_000), 0);
        assert_eq!(mining_subsidy_amount_for_mining_report(1000 * 525_000), 0);
        assert_eq!(
            mining_subsidy_amount_for_mining_report(1_069_352),
            2500_00000000
        );
    }

    #[test]
    fn test_total_circulation() {
        assert_eq!(total_circulation(1), 200000_00000000);
        assert_eq!(total_circulation(10), 2000000_00000000);
        assert_eq!(total_circulation(100), 20000000_00000000);
        assert_eq!(total_circulation(1000), 200000000_00000000);
        assert_eq!(total_circulation(10000), 2000000000_00000000);
        assert_eq!(total_circulation(100_000), 20000000000_00000000);
        assert_eq!(total_circulation(1_000_000), 152500000000_00000000);
        assert_eq!(total_circulation(10_000_000), 209999608993_52125000);
        assert_eq!(total_circulation(100_000_000), TOTAL_ISSUANCE);
        assert_eq!(total_circulation(1_000_000_000), TOTAL_ISSUANCE);
        assert_eq!(total_circulation(524_999), 104999800000_00000000);
        assert_eq!(total_circulation(525_000), 105000000000_00000000);
        assert_eq!(total_circulation(525_001), 105000100000_00000000);
    }

    #[test]
    fn test_find_max_supply() {
        let mut epoch = 0;
        let first_zero_reward_epoch;
        loop {
            let reward_in_epoch = mining_amount_per_mining_report_in_epoch(epoch);
            if reward_in_epoch == 0 {
                first_zero_reward_epoch = epoch;
                break;
            }
            epoch += 1;
        }
        assert_eq!(first_zero_reward_epoch, 45);
        assert_eq!(
            mining_amount_per_mining_report_in_epoch(first_zero_reward_epoch),
            0
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
            209999999999_92650000
        );
    }

    #[test]
    fn test_total_mining_amount() {
        let mut total_mining_amount: u128 = 0;
        for epoch in 0..=100 {
            let per_mining_report_mining_amount = mining_amount_per_mining_report_in_epoch(epoch);
            total_mining_amount +=
                u128::from(per_mining_report_mining_amount * MINING_REPORTS_PER_EPOCH as u64);
        }
        assert_eq!(total_mining_amount, 209999999999_92650000);
        assert_eq!(total_mining_amount, total_circulation(4_294_967_295));
        assert_eq!(TOTAL_ISSUANCE - total_mining_amount, 0);
    }
}

// End of File
