#![allow(warnings)]
mod lib;
use lib::*;
use merlin::Transcript;
use libspartan::{SNARKGens, SNARK, NIZK};
use std::env;
use std::format;
use std::fs::File;
use std::io::Read;
use std::string::String;
use serde::ser::Serialize;
use serde_json::Result;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    let nizk: bool;
    let usage = format!(
        "{} [prove | verify] [--nizk|--snark] <circuit.zkif> <inputs.zkif> <witness.zkif>",
        args.get(0).unwrap()
    );

    // NIZK mode
    match args.get(2) {
        Some(v) if v.clone() == String::from("--nizk") => nizk = true,
        Some(v) if v.clone() == String::from("--snark") => nizk = false,
        _ => {
            nizk=false;
            eprintln!("{}", usage)
        }
    }

    let circuitfn = args.get(3).unwrap();
    let inputsfn = args.get(4).unwrap();
    let witnessfn = args.get(5).unwrap();

    let mut fh = File::open(inputsfn).unwrap();
    let mut bufh = Vec::new();
    fh.read_to_end(&mut bufh).unwrap();
    let mut fcs = File::open(circuitfn).unwrap();
    let mut bufcs = Vec::new();
    fcs.read_to_end(&mut bufcs).unwrap();
    let mut fw = File::open(witnessfn).unwrap();
    let mut bufw = Vec::new();
    fw.read_to_end(&mut bufw).unwrap();


    // Initialize R1csReader
    let reader = R1csReader::new(&mut bufh, &mut bufcs, &mut bufw);
    let r1cs = R1cs::from(reader);

    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    let inst = r1cs.instance(&mut A, &mut B, &mut C);
    let assignment_inputs = r1cs.inputs_assignment();
    let assignment_vars = r1cs.vars_assignment();

    // Check if instance is satisfiable
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    match res {
        Ok(res) =>
            if res {
                eprintln!("Constraints are satisfied by inputs");
            } else {
                std::panic!("Circuit should be satisfied by assignments");
            }
        Err(e) => std::panic!(e)
    }

    // Start timer for prover
    let prover = Instant::now();

    if nizk {
        let gens = r1cs.nizk_public_params();

        // produce a proof of satisfiability
        let mut prover_transcript = Transcript::new(b"nizk_example");
        let proof = NIZK::prove(
            &inst,
            assignment_vars,
            &assignment_inputs,
            &gens,
            &mut prover_transcript,
        );
        eprintln!("Circuit: {}", circuitfn);
        eprintln!("Prover: {}ms", prover.elapsed().as_millis());
        let verifier = Instant::now();
        match args.get(1).unwrap().as_str() {
            "prove" => {
                let json = serde_json::to_string_pretty(&proof).unwrap();
                eprintln!("Prover: {}ms", prover.elapsed().as_millis());
                println!("{}", json)
            },
            "verify" => {
                let mut verifier_transcript = Transcript::new(b"nizk_example");
                assert!(proof
                    .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
                    .is_ok());
                eprintln!("Verifier: {}ms", verifier.elapsed().as_millis());
                eprintln!("NIZK proof verification successful");
            }
            _ => eprintln!("{}", usage),
        }
    } else {

        let gens = r1cs.snark_public_params();
        // create a commitment to the R1CS instance
        let (comm, decomm) = SNARK::encode(&inst, &gens);

        // produce a proof of satisfiability
        let mut prover_transcript = Transcript::new(b"snark_example");
        let proof = SNARK::prove(
            &inst,
            &decomm,
            assignment_vars,
            &assignment_inputs,
            &gens,
            &mut prover_transcript,
        );
        eprintln!("Circuit: {}", circuitfn);
        eprintln!("Prover: {}ms", prover.elapsed().as_millis());
        let verifier = Instant::now();
        match args.get(1).unwrap().as_str() {
            "prove" => {
                let json = serde_json::to_string_pretty(&proof).unwrap();
                eprintln!("Prover: {}ms", prover.elapsed().as_millis());
                println!("{}", json)
            },
            "verify" => {
                let mut verifier_transcript = Transcript::new(b"snark_example");
                assert!(proof
                    .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
                    .is_ok());
                eprintln!("Verifier: {}ms", verifier.elapsed().as_millis());
                eprintln!("SNARK proof verification successful");
            }
            _ => eprintln!("{}", usage),
        }
    }
}
