/// Ed25519 signature verification test harness replicating Agave/Solana behavior.
///
/// Agave uses ed25519-dalek =1.0.1 with:
///   - verify_strict() for transaction sigverify (Signature::verify in sdk/signature/src/lib.rs)
///   - verify_strict() for the ed25519 precompile (after feature gate activation)
///   - verify() was the old precompile behavior before the feature gate
///
/// Usage:
///   ed25519_test <mode> <pubkey_hex> <signature_hex> <message_hex>
///   ed25519_test batch <test_vectors.json> [output.json]
///
/// Modes:
///   strict  - uses PublicKey::verify_strict (what Agave uses)
///   loose   - uses PublicKey::verify (cofactored, old precompile behavior)
///   both    - runs both and reports results
///   batch   - reads test vectors from JSON, runs both, writes results
use ed25519_dalek::{PublicKey, Signature, Verifier};
use std::env;
use std::fs;
use std::process;

mod test_vectors;
use test_vectors::TestVectorFile;

fn verify_strict(pubkey: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    pubkey.verify_strict(msg, sig).is_ok()
}

fn verify_loose(pubkey: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    pubkey.verify(msg, sig).is_ok()
}

fn parse_and_verify(
    pubkey_hex: &str,
    sig_hex: &str,
    msg_hex: &str,
    mode: &str,
) -> (Option<bool>, Option<bool>) {
    let pubkey_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: Invalid pubkey hex: {}", e);
            return (Some(false), Some(false));
        }
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: Invalid signature hex: {}", e);
            return (Some(false), Some(false));
        }
    };
    let msg_bytes = match hex::decode(msg_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: Invalid message hex: {}", e);
            return (Some(false), Some(false));
        }
    };

    if pubkey_bytes.len() != 32 {
        eprintln!("ERROR: pubkey must be 32 bytes, got {}", pubkey_bytes.len());
        return (Some(false), Some(false));
    }
    if sig_bytes.len() != 64 {
        eprintln!(
            "ERROR: signature must be 64 bytes, got {}",
            sig_bytes.len()
        );
        return (Some(false), Some(false));
    }

    // Attempt to deserialize the public key.
    // ed25519-dalek 1.0.1 PublicKey::from_bytes does decompress the point
    // but does NOT reject small-order keys (that's what verify_strict checks).
    let pubkey = match PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("REJECT (pubkey decode failed: {})", e);
            return (Some(false), Some(false));
        }
    };

    // Attempt to deserialize the signature.
    // ed25519-dalek 1.0.1 Signature::from_bytes checks that S < L (scalar reduction).
    let sig = match Signature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("REJECT (signature decode failed: {})", e);
            return (Some(false), Some(false));
        }
    };

    let strict_result = if mode == "strict" || mode == "both" {
        Some(verify_strict(&pubkey, &msg_bytes, &sig))
    } else {
        None
    };

    let loose_result = if mode == "loose" || mode == "both" {
        Some(verify_loose(&pubkey, &msg_bytes, &sig))
    } else {
        None
    };

    (strict_result, loose_result)
}

fn run_single(mode: &str, pubkey_hex: &str, sig_hex: &str, msg_hex: &str) {
    let (strict_result, loose_result) = parse_and_verify(pubkey_hex, sig_hex, msg_hex, mode);

    match mode {
        "strict" => {
            let result = strict_result.unwrap();
            if result {
                println!("ACCEPT");
                process::exit(0);
            } else {
                println!("REJECT");
                process::exit(1);
            }
        }
        "loose" => {
            let result = loose_result.unwrap();
            if result {
                println!("ACCEPT");
                process::exit(0);
            } else {
                println!("REJECT");
                process::exit(1);
            }
        }
        "both" => {
            let s = strict_result.unwrap();
            let l = loose_result.unwrap();
            println!(
                "verify_strict: {}  verify (loose): {}",
                if s { "ACCEPT" } else { "REJECT" },
                if l { "ACCEPT" } else { "REJECT" }
            );
            // Exit 0 if strict accepts (matching Agave behavior)
            if s {
                process::exit(0);
            } else {
                process::exit(1);
            }
        }
        _ => unreachable!(),
    }
}

fn run_batch(input_path: &str, output_path: Option<&str>) {
    let data = fs::read_to_string(input_path).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot read {}: {}", input_path, e);
        process::exit(2);
    });

    let mut tvf: TestVectorFile = serde_json::from_str(&data).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot parse JSON: {}", e);
        process::exit(2);
    });

    println!(
        "Running {} test vectors from {}...",
        tvf.vectors.len(),
        input_path
    );
    println!("{:-<80}", "");

    let mut pass_strict = 0;
    let mut fail_strict = 0;
    let mut pass_loose = 0;
    let mut fail_loose = 0;

    for tv in tvf.vectors.iter_mut() {
        let (strict_result, loose_result) =
            parse_and_verify(&tv.pubkey, &tv.signature, &tv.message, "both");

        let s = strict_result.unwrap();
        let l = loose_result.unwrap();

        tv.result_dalek_strict = Some(if s {
            "ACCEPT".to_string()
        } else {
            "REJECT".to_string()
        });
        tv.result_dalek_loose = Some(if l {
            "ACCEPT".to_string()
        } else {
            "REJECT".to_string()
        });

        if s {
            pass_strict += 1;
        } else {
            fail_strict += 1;
        }
        if l {
            pass_loose += 1;
        } else {
            fail_loose += 1;
        }

        println!(
            "[{}] {} | strict={} loose={}",
            tv.id,
            tv.description,
            if s { "ACCEPT" } else { "REJECT" },
            if l { "ACCEPT" } else { "REJECT" },
        );
    }

    println!("{:-<80}", "");
    println!(
        "verify_strict: {} ACCEPT, {} REJECT",
        pass_strict, fail_strict
    );
    println!(
        "verify (loose): {} ACCEPT, {} REJECT",
        pass_loose, fail_loose
    );

    // Write results
    let out = output_path.unwrap_or(input_path);
    let json = serde_json::to_string_pretty(&tvf).expect("Failed to serialize results");
    fs::write(out, json).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot write {}: {}", out, e);
        process::exit(2);
    });
    println!("Results written to {}", out);
}

fn usage() {
    eprintln!("Ed25519 Test Harness (replicating Agave/Solana ed25519-dalek =1.0.1)");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  ed25519_test strict <pubkey_hex> <sig_hex> <msg_hex>");
    eprintln!("  ed25519_test loose  <pubkey_hex> <sig_hex> <msg_hex>");
    eprintln!("  ed25519_test both   <pubkey_hex> <sig_hex> <msg_hex>");
    eprintln!("  ed25519_test batch  <test_vectors.json> [output.json]");
    eprintln!();
    eprintln!("Modes:");
    eprintln!("  strict - PublicKey::verify_strict (what Agave uses for tx sigverify + precompile)");
    eprintln!("  loose  - PublicKey::verify (cofactored, old precompile before feature gate)");
    eprintln!("  both   - runs both and reports results side-by-side");
    eprintln!("  batch  - reads JSON test vectors, runs both modes, writes results back");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let mode = args[1].as_str();
    match mode {
        "strict" | "loose" | "both" => {
            if args.len() != 5 {
                usage();
            }
            run_single(mode, &args[2], &args[3], &args[4]);
        }
        "batch" => {
            if args.len() < 3 || args.len() > 4 {
                usage();
            }
            let output = if args.len() == 4 {
                Some(args[3].as_str())
            } else {
                None
            };
            run_batch(&args[2], output);
        }
        _ => {
            eprintln!("ERROR: Unknown mode '{}'\n", mode);
            usage();
        }
    }
}
