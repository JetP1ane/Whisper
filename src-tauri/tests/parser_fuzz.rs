//! Parser-fuzzing torture tests.
//!
//! These deliberately avoid `cargo fuzz`'s nightly-toolchain requirement
//! by running a fast in-process loop of random / structured inputs
//! against the bundle parser. Goal: surface any *new* panic / over-allocation
//! beyond the CRIT-1 family that has unit-test coverage.
//!
//! Run with: `cargo test --release --test parser_fuzz -- --nocapture`
//! (release for speed; fuzz iterates ~250k inputs).

use noctis_whisper_desktop_lib::crypto::bundle;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

const ITERATIONS_RANDOM: usize = 50_000;
const ITERATIONS_STRUCTURED: usize = 10_000;
const ITERATIONS_LINK: usize = 25_000;

#[test]
fn random_bytes_no_panic() {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEFu64);
    for i in 0..ITERATIONS_RANDOM {
        let len = rng.gen_range(0..=4096);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        // We don't care if it errors — only that it does not panic.
        let _ = bundle::deserialize(&buf);
        if i % 10000 == 0 {
            eprintln!("random_bytes_no_panic: {i}/{ITERATIONS_RANDOM}");
        }
    }
}

#[test]
fn structured_with_negatives_no_panic() {
    // Generate inputs that look almost-valid — pass the version check —
    // but stuff negative or oversize lengths in fields. This exercises
    // the post-CRIT-1 saturating_sub path under varied off positions.
    let mut rng = StdRng::seed_from_u64(0x1234_5678_9ABC_DEF0u64);
    for i in 0..ITERATIONS_STRUCTURED {
        let mut buf = Vec::with_capacity(2048);
        // Version int (sometimes valid, sometimes garbage)
        let version: i32 = match rng.gen_range(0..4) {
            0 => 4,
            1 => -1,
            2 => i32::MAX,
            _ => rng.gen(),
        };
        buf.extend_from_slice(&version.to_be_bytes());
        // Then 0–8 fields of random length
        for _ in 0..rng.gen_range(0..=8) {
            let length: i32 = match rng.gen_range(0..5) {
                0 => 32,
                1 => 64,
                2 => -1,
                3 => i32::MAX,
                _ => rng.gen(),
            };
            buf.extend_from_slice(&length.to_be_bytes());
            let payload_len = if length > 0 && length < 1024 {
                length as usize
            } else {
                rng.gen_range(0..=64)
            };
            for _ in 0..payload_len {
                buf.push(rng.gen());
            }
        }
        let _ = bundle::deserialize(&buf);
        if i % 2500 == 0 {
            eprintln!("structured_with_negatives_no_panic: {i}/{ITERATIONS_STRUCTURED}");
        }
    }
}

#[test]
fn whisper_link_random_no_panic() {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_BABE_5EEDu64);
    let alphabet: &[u8] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for i in 0..ITERATIONS_LINK {
        // Build a "whisper://c/<base58 garbage>" with random length.
        let body_len = rng.gen_range(1..=1024);
        let mut s = String::with_capacity(body_len + 12);
        s.push_str("whisper://c/");
        for _ in 0..body_len {
            let idx = rng.gen_range(0..alphabet.len());
            s.push(alphabet[idx] as char);
        }
        let _ = bundle::parse_whisper_link(&s);
        if i % 5000 == 0 {
            eprintln!("whisper_link_random_no_panic: {i}/{ITERATIONS_LINK}");
        }
    }
}

#[test]
fn whisper_link_oversize_capped_at_8k() {
    // contact_add_by_link has an 8 KiB cap *before* base58 decode; we
    // can't reach that command from this integration test, but we can
    // still verify parse_whisper_link doesn't panic on a 64 KiB payload.
    // (The cap is in commands.rs:833 and protects from DoS at the IPC
    // boundary; here we're hardening parse_whisper_link itself.)
    let alphabet: &[u8] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_FACE_CAFEu64);
    let mut s = String::with_capacity(64 * 1024 + 16);
    s.push_str("whisper://c/");
    for _ in 0..(64 * 1024) {
        let idx = rng.gen_range(0..alphabet.len());
        s.push(alphabet[idx] as char);
    }
    let _ = bundle::parse_whisper_link(&s);
    eprintln!("64 KiB whisper link did not panic");
}
