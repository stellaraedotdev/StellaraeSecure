use crate::error::{Error, Result};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const TOTP_DIGITS: u32 = 6;
const TOTP_PERIOD_SECONDS: i64 = 30;
const TOTP_SECRET_BYTES: usize = 20;

pub fn generate_totp_secret_base32() -> String {
  let mut secret = [0u8; TOTP_SECRET_BYTES];
  rand::rng().fill_bytes(&mut secret);
  BASE32_NOPAD.encode(&secret)
}

fn decode_secret(secret_base32: &str) -> Result<Vec<u8>> {
  BASE32_NOPAD
    .decode(secret_base32.trim().as_bytes())
    .map_err(|_| Error::ValidationError("Invalid TOTP secret encoding".to_string()))
}

fn generate_code(secret: &[u8], timestamp: i64) -> Result<u32> {
  let counter = (timestamp / TOTP_PERIOD_SECONDS) as u64;
  let mut msg = [0u8; 8];
  msg.copy_from_slice(&counter.to_be_bytes());

  let mut mac = HmacSha1::new_from_slice(secret)
    .map_err(|_| Error::InternalServerError)?;
  mac.update(&msg);
  let digest = mac.finalize().into_bytes();

  let offset = (digest[19] & 0x0f) as usize;
  let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
    | (u32::from(digest[offset + 1]) << 16)
    | (u32::from(digest[offset + 2]) << 8)
    | u32::from(digest[offset + 3]);

  Ok(binary % 10u32.pow(TOTP_DIGITS))
}

pub fn verify_totp_code(secret_base32: &str, code: &str, now_ts: i64) -> Result<bool> {
  let parsed_code: u32 = code
    .trim()
    .parse()
    .map_err(|_| Error::ValidationError("TOTP code must be numeric".to_string()))?;

  let secret = decode_secret(secret_base32)?;

  // Allow +-1 period for clock skew tolerance.
  for drift in [-1_i64, 0, 1] {
    let candidate_ts = now_ts + drift * TOTP_PERIOD_SECONDS;
    if generate_code(&secret, candidate_ts)? == parsed_code {
      return Ok(true);
    }
  }

  Ok(false)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn generated_secret_is_base32() {
    let secret = generate_totp_secret_base32();
    assert!(!secret.is_empty());
    assert!(decode_secret(&secret).is_ok());
  }

  #[test]
  fn verify_rejects_non_numeric_code() {
    let secret = generate_totp_secret_base32();
    let result = verify_totp_code(&secret, "abc123", 1_700_000_000);
    assert!(result.is_err());
  }
}
