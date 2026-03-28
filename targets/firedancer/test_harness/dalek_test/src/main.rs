//! Dalek Ed25519 test harness for differential testing against Firedancer.
//!
//! Reads test vectors from test_vectors.json and runs both verify_strict()
//! and verify() from ed25519-dalek v1.0.1, outputting results as JSON.
//!
//! This is the CRITICAL test for detecting consensus divergence between
//! Firedancer and Agave (which uses ed25519-dalek v1.0.1 verify_strict).

use ed25519_dalek::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
struct TestVectorsFile {
    vectors: Vec<TestVector>,
    #[serde(flatten)]
    _extra: serde_json::Value,
}

#[derive(Deserialize, Clone)]
struct TestVector {
    id: String,
    #[serde(default)]
    hypothesis: String,
    #[serde(default)]
    description: String,
    pubkey: String,
    signature: String,
    message: String,
    #[serde(default = "default_unknown")]
    expected_firedancer: String,
    #[serde(default = "default_unknown")]
    expected_dalek_strict: String,
    #[serde(default = "default_unknown")]
    expected_dalek_loose: String,
}

fn default_unknown() -> String {
    "unknown".to_string()
}

#[derive(Serialize)]
struct TestResult {
    id: String,
    description: String,
    result_dalek_strict: String,
    result_dalek_loose: String,
    strict_error: Option<String>,
    loose_error: Option<String>,
    expected_dalek_strict: String,
    expected_firedancer: String,
    match_strict: bool,
    divergence_fd_vs_dalek: bool,
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

fn run_verify(vec: &TestVector) -> TestResult {
    let pub_bytes = hex_decode(&vec.pubkey).unwrap_or_default();
    let sig_bytes = hex_decode(&vec.signature).unwrap_or_default();
    let msg_bytes = if vec.message.is_empty() {
        vec![]
    } else {
        hex_decode(&vec.message).unwrap_or_default()
    };

    // Try verify_strict
    let (strict_result, strict_err) = match (
        PublicKey::from_bytes(&pub_bytes),
        Signature::from_bytes(&sig_bytes),
    ) {
        (Ok(pk), Ok(sig)) => match pk.verify_strict(&msg_bytes, &sig) {
            Ok(()) => ("ACCEPT".to_string(), None),
            Err(e) => ("REJECT".to_string(), Some(format!("{}", e))),
        },
        (Err(e), _) => ("REJECT".to_string(), Some(format!("pubkey: {}", e))),
        (_, Err(e)) => ("REJECT".to_string(), Some(format!("signature: {}", e))),
    };

    // Try verify (loose/cofactored)
    let (loose_result, loose_err) = match (
        PublicKey::from_bytes(&pub_bytes),
        Signature::from_bytes(&sig_bytes),
    ) {
        (Ok(pk), Ok(sig)) => {
            use ed25519_dalek::Verifier;
            match pk.verify(&msg_bytes, &sig) {
                Ok(()) => ("ACCEPT".to_string(), None),
                Err(e) => ("REJECT".to_string(), Some(format!("{}", e))),
            }
        }
        (Err(e), _) => ("REJECT".to_string(), Some(format!("pubkey: {}", e))),
        (_, Err(e)) => ("REJECT".to_string(), Some(format!("signature: {}", e))),
    };

    let match_strict = if vec.expected_dalek_strict != "unknown" {
        strict_result == vec.expected_dalek_strict
    } else {
        true
    };

    // Check for divergence: Firedancer ACCEPT but Dalek strict REJECT
    let divergence = vec.expected_firedancer == "ACCEPT" && strict_result == "REJECT";

    TestResult {
        id: vec.id.clone(),
        description: vec.description.clone(),
        result_dalek_strict: strict_result,
        result_dalek_loose: loose_result,
        strict_error: strict_err,
        loose_error: loose_err,
        expected_dalek_strict: vec.expected_dalek_strict.clone(),
        expected_firedancer: vec.expected_firedancer.clone(),
        match_strict,
        divergence_fd_vs_dalek: divergence,
    }
}

fn main() {
    // Find test vectors file
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let candidates = vec![
        Path::new("../test_vectors.json").to_path_buf(),
        Path::new("../noncanon_test_vectors.json").to_path_buf(),
        Path::new("test_vectors.json").to_path_buf(),
        Path::new("noncanon_test_vectors.json").to_path_buf(),
    ];

    // Process all JSON files found
    let mut all_results = Vec::new();
    let mut files_processed = Vec::new();

    for candidate in &candidates {
        if candidate.exists() {
            eprintln!("Loading: {}", candidate.display());
            let content = fs::read_to_string(candidate).expect("Failed to read file");
            let data: TestVectorsFile =
                serde_json::from_str(&content).expect("Failed to parse JSON");

            files_processed.push(candidate.display().to_string());

            for vec in &data.vectors {
                // Skip if we already have this ID
                if all_results.iter().any(|r: &TestResult| r.id == vec.id) {
                    continue;
                }
                let result = run_verify(vec);
                all_results.push(result);
            }
        }
    }

    if all_results.is_empty() {
        eprintln!("ERROR: No test vector files found. Run from the test_harness directory.");
        std::process::exit(1);
    }

    // Print results
    println!("========================================================================");
    println!("Dalek Ed25519 Verification Results (ed25519-dalek v1.0.1)");
    println!("========================================================================");
    println!("Files: {:?}", files_processed);
    println!();

    let mut divergences = Vec::new();
    let mut mismatches = Vec::new();

    for r in &all_results {
        let strict_flag = if !r.match_strict { " *** MISMATCH ***" } else { "" };
        let div_flag = if r.divergence_fd_vs_dalek {
            " !!! DIVERGENCE !!!"
        } else {
            ""
        };

        println!("[{}]", r.id);
        println!("  strict: {} {}", r.result_dalek_strict, r.strict_error.as_deref().unwrap_or(""));
        println!("  loose:  {} {}", r.result_dalek_loose, r.loose_error.as_deref().unwrap_or(""));
        println!(
            "  expected_strict: {}  expected_fd: {}{}{}",
            r.expected_dalek_strict, r.expected_firedancer, strict_flag, div_flag
        );
        println!();

        if r.divergence_fd_vs_dalek {
            divergences.push(r);
        }
        if !r.match_strict {
            mismatches.push(r);
        }
    }

    // Summary
    println!("========================================================================");
    println!("SUMMARY");
    println!("========================================================================");
    println!("Total vectors: {}", all_results.len());
    println!(
        "Strict ACCEPT: {}",
        all_results
            .iter()
            .filter(|r| r.result_dalek_strict == "ACCEPT")
            .count()
    );
    println!(
        "Strict REJECT: {}",
        all_results
            .iter()
            .filter(|r| r.result_dalek_strict == "REJECT")
            .count()
    );
    println!();

    if !mismatches.is_empty() {
        println!("MISMATCHES (result != expected):");
        for r in &mismatches {
            println!(
                "  {}: got={}, expected={}",
                r.id, r.result_dalek_strict, r.expected_dalek_strict
            );
        }
        println!();
    }

    if !divergences.is_empty() {
        println!("!!! CONSENSUS DIVERGENCES (Firedancer ACCEPT, Dalek REJECT) !!!");
        for r in &divergences {
            println!("  {}: {}", r.id, r.description);
        }
    } else {
        println!("No consensus divergences detected (Firedancer expected=ACCEPT and Dalek=REJECT).");
    }

    // Check the CRITICAL non-canonical cases: where Firedancer emulator
    // reaches "equation check failed" (meaning decompression succeeded)
    // but Dalek rejects. Even if the final result is the same (both REJECT),
    // the REASON differs, indicating a behavioral divergence.
    println!();
    println!("========================================================================");
    println!("NON-CANONICAL R DECOMPRESSION ANALYSIS");
    println!("========================================================================");
    println!();
    println!("Key question: Does Dalek reject non-canonical R at decompression,");
    println!("or does it reduce y mod p (like Firedancer)?");
    println!();

    // Check non-canonical R vectors specifically
    let noncanon_ids: Vec<&str> = all_results
        .iter()
        .filter(|r| r.id.contains("noncanon_R_y_p_plus") || r.id.contains("noncanon_R_y3"))
        .map(|r| r.id.as_str())
        .collect();

    for r in &all_results {
        if r.id.contains("noncanon_R_y_p_plus") || r.id.contains("noncanon_R_y3") {
            let dalek_reason = r
                .strict_error
                .as_deref()
                .unwrap_or("(no error - ACCEPT)");
            println!(
                "  {}: strict={} reason=\"{}\"",
                r.id, r.result_dalek_strict, dalek_reason
            );
        }
    }

    println!();
    println!("If Dalek errors mention 'non-canonical' or fail at Signature::from_bytes,");
    println!("while Firedancer only fails at 'equation check', this proves the behavioral");
    println!("divergence exists. A valid signature with non-canonical R would then cause");
    println!("a consensus split.");

    // Save results as JSON
    let output_path = Path::new("dalek_results.json");
    let json = serde_json::to_string_pretty(&all_results).unwrap();
    fs::write(output_path, &json).expect("Failed to write results");
    eprintln!("\nResults saved to: {}", output_path.display());
}
