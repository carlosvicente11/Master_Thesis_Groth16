//! Field-operation counters (thesis instrumentation patch).
//!
//! This module is NOT part of upstream ark-ff. It is a local patch used to
//! measure how many base-field (`Fq`) and scalar-field (`Fr`) `mul` / `square`
//! / `inverse` calls a Groth16 verification issues, to establish a baseline for
//! the Cortex-M4 assembly optimization work.
//!
//! Counting is done with relaxed atomics so it works in `no_std` and needs no
//! `unsafe`. The hot-path overhead (a `type_name` substring check + one atomic
//! increment) is irrelevant for a one-shot call-count measurement.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub enum Op {
    Mul,
    Square,
    Inverse,
}

/// Master switch. When `false` (the default) the `bump*` helpers do nothing
/// beyond one relaxed atomic load, so normal verification keeps a clean timing
/// baseline. Turn on with [`set_enabled`] only while measuring call counts.
static ENABLED: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub static FQ_MUL: AtomicU64 = AtomicU64::new(0);
pub static FQ_SOP: AtomicU64 = AtomicU64::new(0);
pub static FQ_SQUARE: AtomicU64 = AtomicU64::new(0);
pub static FQ_INVERSE: AtomicU64 = AtomicU64::new(0);
pub static FR_MUL: AtomicU64 = AtomicU64::new(0);
pub static FR_SOP: AtomicU64 = AtomicU64::new(0);
pub static FR_SQUARE: AtomicU64 = AtomicU64::new(0);
pub static FR_INVERSE: AtomicU64 = AtomicU64::new(0);

/// Increment the counter for `op` on the field identified by `config_type_name`
/// (the `core::any::type_name` of the `MontConfig` type). BN254's scalar-field
/// config is `...fr::FrConfig`; everything else (base field, used by the whole
/// Fp2/Fp6/Fp12 tower) is bucketed as `Fq`.
#[inline]
pub fn bump(config_type_name: &'static str, op: Op) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let is_fr = config_type_name.contains("FrConfig") || config_type_name.contains("fr::");
    let counter = match (is_fr, op) {
        (false, Op::Mul) => &FQ_MUL,
        (false, Op::Square) => &FQ_SQUARE,
        (false, Op::Inverse) => &FQ_INVERSE,
        (true, Op::Mul) => &FR_MUL,
        (true, Op::Square) => &FR_SQUARE,
        (true, Op::Inverse) => &FR_INVERSE,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Add `n` to the `Mul` counter of the field identified by `config_type_name`.
/// Used for `sum_of_products`, which performs `M` base multiplications in one
/// call (Fp2 multiplication routes through this instead of `mul_assign`).
#[inline]
pub fn bump_mul_n(config_type_name: &'static str, n: u64) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let is_fr = config_type_name.contains("FrConfig") || config_type_name.contains("fr::");
    let counter = if is_fr { &FR_SOP } else { &FQ_SOP };
    counter.fetch_add(n, Ordering::Relaxed);
}

/// Zero all counters. Call before the region you want to measure.
pub fn reset() {
    for c in [
        &FQ_MUL, &FQ_SOP, &FQ_SQUARE, &FQ_INVERSE, &FR_MUL, &FR_SOP, &FR_SQUARE, &FR_INVERSE,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Snapshot {
    /// Direct `mul_assign` calls.
    pub fq_mul: u64,
    /// Base multiplications performed inside `sum_of_products` (Fp2 mul path).
    pub fq_sop: u64,
    pub fq_square: u64,
    pub fq_inverse: u64,
    pub fr_mul: u64,
    pub fr_sop: u64,
    pub fr_square: u64,
    pub fr_inverse: u64,
}

/// Read the current counter values.
pub fn snapshot() -> Snapshot {
    Snapshot {
        fq_mul: FQ_MUL.load(Ordering::Relaxed),
        fq_sop: FQ_SOP.load(Ordering::Relaxed),
        fq_square: FQ_SQUARE.load(Ordering::Relaxed),
        fq_inverse: FQ_INVERSE.load(Ordering::Relaxed),
        fr_mul: FR_MUL.load(Ordering::Relaxed),
        fr_sop: FR_SOP.load(Ordering::Relaxed),
        fr_square: FR_SQUARE.load(Ordering::Relaxed),
        fr_inverse: FR_INVERSE.load(Ordering::Relaxed),
    }
}
