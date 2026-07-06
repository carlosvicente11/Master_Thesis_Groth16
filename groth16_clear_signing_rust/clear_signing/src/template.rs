//! Fixed-position text template for ERC-20 transfer clear signing (v1):
//!
//! ```text
//! Send IIIIIIIIII.FFFFFF USDC to 0x<40 lowercase hex chars>
//! ```
//!
//! - 10 integer digits + '.' + 6 fraction digits, zero-padded fixed width, so
//!   the raw amount must be < 10^16 base units (enforced in-circuit by 24
//!   leading zero bytes in the amount slot + the 16-digit decimal equality).
//! - Total rendered length 73 bytes, space-padded to `TEXT_BYTES` (96).
//! - The circuit enforces byte-for-byte equality against this layout; the
//!   native renderer here is what the prover (and tests, and later the chip
//!   E2E harness) uses to build T.

use crate::circuit::{CALLDATA_BYTES, TEXT_BYTES};

pub const SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)

pub const AMOUNT_INT_DIGITS: usize = 10;
pub const AMOUNT_FRAC_DIGITS: usize = 6; // USDC decimals
pub const AMOUNT_DIGITS: usize = AMOUNT_INT_DIGITS + AMOUNT_FRAC_DIGITS;
pub const AMOUNT_MAX: u64 = 10u64.pow(AMOUNT_DIGITS as u32); // exclusive bound

pub const PREFIX: &[u8] = b"Send ";
pub const MIDDLE: &[u8] = b" USDC to 0x";

pub const INT_POS: usize = PREFIX.len(); // 5
pub const DOT_POS: usize = INT_POS + AMOUNT_INT_DIGITS; // 15
pub const FRAC_POS: usize = DOT_POS + 1; // 16
pub const MIDDLE_POS: usize = FRAC_POS + AMOUNT_FRAC_DIGITS; // 22
pub const HEX_POS: usize = MIDDLE_POS + MIDDLE.len(); // 33
pub const HEX_END: usize = HEX_POS + 40; // 73

/// Calldata layout: selector | 12 zero bytes | 20-byte to | 24 zero bytes | 8-byte BE amount.
pub const TO_POS: usize = 4 + 12; // 16
pub const AMOUNT_POS: usize = 36 + 24; // 60

pub fn build_transfer_calldata(to: &[u8; 20], amount: u64) -> Vec<u8> {
    let mut c = vec![0u8; CALLDATA_BYTES];
    c[..4].copy_from_slice(&SELECTOR);
    c[TO_POS..TO_POS + 20].copy_from_slice(to);
    c[AMOUNT_POS..].copy_from_slice(&amount.to_be_bytes());
    c
}

/// Render the canonical text for a transfer calldata. Fails on malformed
/// calldata (wrong selector, nonzero padding, amount >= 10^16).
pub fn render_transfer_text(calldata: &[u8]) -> Result<Vec<u8>, String> {
    if calldata.len() != CALLDATA_BYTES {
        return Err(format!("calldata must be {CALLDATA_BYTES} bytes"));
    }
    if calldata[..4] != SELECTOR {
        return Err("wrong selector".into());
    }
    if calldata[4..TO_POS].iter().any(|&b| b != 0) {
        return Err("nonzero address padding".into());
    }
    if calldata[36..AMOUNT_POS].iter().any(|&b| b != 0) {
        return Err("amount exceeds 8 bytes".into());
    }
    let amount = u64::from_be_bytes(calldata[AMOUNT_POS..].try_into().unwrap());
    if amount >= AMOUNT_MAX {
        return Err(format!("amount must be < 10^{AMOUNT_DIGITS}"));
    }

    let mut t = Vec::with_capacity(TEXT_BYTES);
    t.extend_from_slice(PREFIX);
    let int_part = amount / 10u64.pow(AMOUNT_FRAC_DIGITS as u32);
    let frac_part = amount % 10u64.pow(AMOUNT_FRAC_DIGITS as u32);
    t.extend_from_slice(format!("{int_part:0AMOUNT_INT_DIGITS$}").as_bytes());
    t.push(b'.');
    t.extend_from_slice(format!("{frac_part:0AMOUNT_FRAC_DIGITS$}").as_bytes());
    t.extend_from_slice(MIDDLE);
    for &b in &calldata[TO_POS..TO_POS + 20] {
        t.push(HEX_LOWER[(b >> 4) as usize]);
        t.push(HEX_LOWER[(b & 0x0f) as usize]);
    }
    t.resize(TEXT_BYTES, b' ');
    Ok(t)
}

const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_expected_layout() {
        let calldata = build_transfer_calldata(&[0x11; 20], 12_500_000);
        let text = render_transfer_text(&calldata).unwrap();
        assert_eq!(text.len(), TEXT_BYTES);
        assert_eq!(
            &text[..HEX_END],
            b"Send 0000000012.500000 USDC to 0x1111111111111111111111111111111111111111"
                as &[u8]
        );
        assert!(text[HEX_END..].iter().all(|&b| b == b' '));
    }

    #[test]
    fn rejects_malformed_calldata() {
        let good = build_transfer_calldata(&[0x22; 20], 1);
        let mut bad = good.clone();
        bad[0] = 0xde;
        assert!(render_transfer_text(&bad).is_err()); // selector

        let mut bad = good.clone();
        bad[5] = 1;
        assert!(render_transfer_text(&bad).is_err()); // address padding

        let mut bad = good.clone();
        bad[40] = 1;
        assert!(render_transfer_text(&bad).is_err()); // amount padding

        let mut bad = good;
        bad[AMOUNT_POS..].copy_from_slice(&AMOUNT_MAX.to_be_bytes());
        assert!(render_transfer_text(&bad).is_err()); // amount too large
    }
}
