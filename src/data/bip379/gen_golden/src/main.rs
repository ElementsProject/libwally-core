use std::collections::BTreeMap;

use bitcoin::hashes::{ripemd160, sha256, Hash};
use bitcoin::hex::DisplayHex;
use miniscript::miniscript::satisfy::{Preimage32, Satisfier};
use miniscript::{Miniscript, Segwitv0};

// SHA256([0x12;32]) and RIPEMD160([0x78;32]) — must match test_satisfier_diff.py
const SHA256_PRE: [u8; 32] = [0x12u8; 32];
const RIPEMD160_PRE: [u8; 32] = [0x78u8; 32];
const SHA256_H: &str = "b6acca81a0939a856c35e4c4188e95b91731aab1d4629a4cee79dd09ded4fc94";
const RIPEMD_H: &str = "6646adac9fb158a6df66130746d48a0e7f9db390";

struct CorpusSatisfier {
    expected_sha256: sha256::Hash,
    expected_ripemd160: ripemd160::Hash,
}

impl CorpusSatisfier {
    fn new() -> Self {
        Self {
            expected_sha256: sha256::Hash::hash(&SHA256_PRE),
            expected_ripemd160: ripemd160::Hash::hash(&RIPEMD160_PRE),
        }
    }
}

impl Satisfier<bitcoin::PublicKey> for CorpusSatisfier {
    fn lookup_sha256(&self, h: &sha256::Hash) -> Option<Preimage32> {
        if h == &self.expected_sha256 {
            Some(SHA256_PRE)
        } else {
            None
        }
    }

    fn lookup_ripemd160(&self, h: &ripemd160::Hash) -> Option<Preimage32> {
        if h == &self.expected_ripemd160 {
            Some(RIPEMD160_PRE)
        } else {
            None
        }
    }
    // lookup_hash256, lookup_hash160, check_after, check_older all return None/false
    // (defaults) — hash256/hash160 can't be satisfied with our preimages; we don't
    // model timelocks so golden data stays stable regardless of tx fields.
}

fn sub_h(ms: &str) -> String {
    let ms = ms.replace("hash256(H)", &format!("hash256({})", SHA256_H));
    let ms = ms.replace("sha256(H)", &format!("sha256({})", SHA256_H));
    let ms = ms.replace("hash160(H)", &format!("hash160({})", RIPEMD_H));
    ms.replace("ripemd160(H)", &format!("ripemd160({})", RIPEMD_H))
}

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let vectors_path = format!("{}/../miniscript_vectors.json", manifest_dir);
    let golden_path = format!("{}/../satisfier_golden.json", manifest_dir);

    let vectors_data = std::fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", vectors_path, e));
    let vectors: serde_json::Value =
        serde_json::from_str(&vectors_data).expect("failed to parse miniscript_vectors.json");

    let satisfier = CorpusSatisfier::new();
    let mut golden = BTreeMap::<String, Vec<String>>::new();

    let valid_cases = vectors["valid_cases"]
        .as_array()
        .expect("valid_cases not array");

    for tc in valid_cases {
        let ms_raw = tc["miniscript"].as_str().expect("miniscript not string");
        let substituted = sub_h(ms_raw);

        let ms = match Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str_insane(&substituted) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let stack = match ms.satisfy_malleable(&satisfier) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let script_hex = format!("{:x}", ms.encode());
        let mut witness: Vec<String> = stack.iter().map(|item| item.to_lower_hex_string()).collect();
        witness.push(script_hex);

        golden.insert(substituted, witness);
    }

    let out = serde_json::to_string_pretty(&golden).expect("failed to serialize golden");
    std::fs::write(&golden_path, out)
        .unwrap_or_else(|e| panic!("failed to write {}: {}", golden_path, e));

    println!("wrote {} golden entries to {}", golden.len(), golden_path);
}
