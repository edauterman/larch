#![allow(warnings)]
pub extern crate flatbuffers;

pub mod zkinterface_generated;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK, NIZKGens, NIZK};
use merlin::Transcript;
use std::cmp::max;
use std::fmt;
use std::fs::File;
use std::io::Read;
use zkinterface_generated::zkinterface as fb;

#[derive(Debug)]
pub struct FlatError {
    details: String,
}

impl FlatError {
    fn new(msg: &str) -> FlatError {
        FlatError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for FlatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl std::error::Error for FlatError {
    fn description(&self) -> &str {
        &self.details
    }
}

pub type Result<T> = std::result::Result<T, FlatError>;

impl From<std::io::Error> for FlatError {
    fn from(error: std::io::Error) -> Self {
        let msg = format!("{}", error);
        FlatError::new(&msg)
    }
}

#[derive(Debug)]
pub struct Variable {
    id: usize,
    value: [u8; 32],
}

#[derive(Debug)]
pub struct QEQ {
    a: Vec<Variable>,
    b: Vec<Variable>,
    c: Vec<Variable>,
}
#[derive(Debug)]
pub struct R1cs {
    inputs: Vec<Variable>,
    witness: Vec<Variable>,
    field_max: [u8; 32],
    constraints: Vec<QEQ>,
    non_zero_entries: usize,
}

#[derive(Debug)]
pub struct R1csReader<'a> {
    header: fb::CircuitHeader<'a>,
    cs: fb::ConstraintSystem<'a>,
    witness: fb::Witness<'a>,
}

impl R1cs {
    pub fn new<'a>(r: R1csReader<'a>) -> R1cs {
        R1cs::from(r)
    }
    pub fn inputs_assignment(&self) -> InputsAssignment {
        let mut inputs = Vec::new();
        for Variable { id, value } in &self.inputs {
            inputs.push(value.clone());
        }
        InputsAssignment::new(&inputs).unwrap()
    }

    pub fn vars_assignment(&self) -> VarsAssignment {
        let mut vars = Vec::new();
        for Variable { id, value } in &self.witness {
            vars.push(value.clone());
        }
        VarsAssignment::new(&vars).unwrap()
    }

    // Translate from whatever naming scheme in the input to Spartan's naming Scheme z = [vars, 1, inputs]
    fn translate(&self, id: &usize) -> usize {
        let num_vars = self.witness.len();
        match self.witness.iter().position(|v| v.id == *id) {
            Some(idx) => return idx,
            None => match self.inputs.iter().position(|v| v.id == *id) {
                Some(idx) => return idx + num_vars + 1,
                None => return num_vars
            }
        }
    }

    pub fn instance(
        &self,
        A: &mut Vec<(usize, usize, [u8; 32])>,
        B: &mut Vec<(usize, usize, [u8; 32])>,
        C: &mut Vec<(usize, usize, [u8; 32])>,
    ) -> Instance {
        let num_vars = self.witness.len();
        let mut i = 0;

        for QEQ { a, b, c } in &self.constraints {
            for Variable { id, value } in a {
                A.push((i, self.translate(id), value.clone()));
            }
            for Variable { id, value } in b {
                B.push((i, self.translate(id), value.clone()));
            }
            for Variable { id, value } in c {
                C.push((i, self.translate(id), value.clone()));
            }
            i += 1;
        }
        Instance::new(
            self.constraints.len(),
            self.witness.len(),
            self.inputs.len(),
            &A,
            &B,
            &C,
        )
        .unwrap()
    }

    pub fn snark_public_params(&self) -> SNARKGens {
        SNARKGens::new(
            self.constraints.len(),
            self.witness.len(),
            self.inputs.len(),
            self.non_zero_entries,
        )
    }

    pub fn nizk_public_params(&self) -> NIZKGens {
        NIZKGens::new(
            self.constraints.len(),
            self.witness.len(),
            self.inputs.len()
        )
    }
}

impl<'a> R1csReader<'a> {
    pub fn new(
        circuit_header_buffer: &'a mut Vec<u8>,
        constraints_buffer: &'a mut Vec<u8>,
        witness_buffer: &'a mut Vec<u8>,
    ) -> Self {
        // Read constraint system
/*        let witness = fb::get_root_as_root(witness_buffer)
            .message_as_witness()
            .ok_or(FlatError::new("Input file is not a flatbuffer Witness"))
            .unwrap()
            .clone();
*/

        println!("about to get root as root");
        let rt = fb::get_root_as_root(constraints_buffer);
        println!("finished root as root");
        if rt.message_type() == fb::Message::ConstraintSystem {
            println!("Message is at least right type");
        }
        if rt.message_type() == fb::Message::CircuitHeader {
            println!("Message is type circ header");
        }
        if rt.message_type() == fb::Message::Witness {
            println!("Message is type witness");
        }
        if rt.message_type() == fb::Message::Command {
            println!("Message is type command");
        }
        if rt.message_type() == fb::Message::NONE {
            println!("Message is type NONE");
        }
        //let cs = fb::get_root_as_root(constraints_buffer)
        let cs_tmp = rt.message_as_constraint_system();
        println!("finished msg as constraint sys");
        let cs = cs_tmp
            .ok_or(FlatError::new(
                "Input file is not a flatbuffer Constraint System",
            ))
            .unwrap();


        // Read circuit header, includes inputs
        if (fb::get_root_as_root(circuit_header_buffer).message_type() == fb::Message::CircuitHeader) {
            println!("circuit header right msg type");
        }
         if (fb::get_root_as_root(circuit_header_buffer).message_type() == fb::Message::ConstraintSystem) {
            println!("circuit header msg type constraint");
        }
        if (fb::get_root_as_root(circuit_header_buffer).message_type() == fb::Message::Witness) {
            println!("circuit header msg type witness");
        }
        if (fb::get_root_as_root(circuit_header_buffer).message_type() == fb::Message::Command) {
            println!("circuit header msg type command");
        }
        if (fb::get_root_as_root(circuit_header_buffer).message_type() == fb::Message::NONE) {
            println!("circuit header msg type NONE");
        }
        let header = fb::get_root_as_root(circuit_header_buffer)
            .message_as_circuit_header()
            .ok_or(FlatError::new(
                "Input file is not a flatbuffer Circuit Header",
            ))
            .unwrap();

/*        // Read constraint system
        let cs = fb::get_root_as_root(constraints_buffer)
            .message_as_constraint_system()
            .ok_or(FlatError::new(
                "Input file is not a flatbuffer Constraint System",
            ))
            .unwrap();*/

        // Read witnesses
        let witness = fb::get_root_as_root(witness_buffer)
            .message_as_witness()
            .ok_or(FlatError::new("Input file is not a flatbuffer Witness"))
            .unwrap()
            .clone();


        R1csReader {
            header,
            cs,
            witness,
        }
    }
}

impl<'a> From<R1csReader<'a>> for R1cs {
    fn from(reader: R1csReader<'a>) -> R1cs {
        // Helper to make [(k,v)] into Rust [(k',v')]
        fn get_variables<'a>(fbvs: fb::Variables<'a>) -> Vec<Variable> {
            let var_ids = fbvs.variable_ids().unwrap();
            let values = fbvs.values().unwrap();

            let num_vars = var_ids.len();

            // To return
            let mut vs = Vec::new();

            if num_vars == 0 {
                return Vec::new();
            }
            let ba_len = values.len() / num_vars;

            for i in 0..num_vars {
                let mut val = [0; 32];
                val[..ba_len].clone_from_slice(&values[i * ba_len..(i + 1) * ba_len]);
                let v = Variable {
                    id: var_ids.get(i) as usize,
                    value: val,
                };
                vs.push(v);
            }
            vs
        }

        let inputs = get_variables(reader.header.instance_variables().unwrap());
        let mut field_max = [0u8; 32];
        field_max.clone_from_slice(reader.header.field_maximum().unwrap());

        let witness = get_variables(reader.witness.assigned_variables().unwrap());

        let mut constraints = Vec::new();

        let mut num_non_zero_a = 0;
        let mut num_non_zero_b = 0;
        let mut num_non_zero_c = 0;

        if reader.cs.constraints().unwrap().len() == 0 {
            panic!("No constraints given!");
        }

        for ctr in reader.cs.constraints().unwrap() {
            let a = get_variables(ctr.linear_combination_a().unwrap());
            let b = get_variables(ctr.linear_combination_b().unwrap());
            let c = get_variables(ctr.linear_combination_c().unwrap());

            num_non_zero_a += a.iter().filter(|&v| v.value.iter().any(|&x| x != 0)).count();
            num_non_zero_b += b.iter().filter(|&v| v.value.iter().any(|&x| x != 0)).count();
            num_non_zero_c += c.iter().filter(|&v| v.value.iter().any(|&x| x != 0)).count();
            constraints.push(QEQ { a, b, c });
        }

        let non_zero_entries = max(num_non_zero_a, max(num_non_zero_b, num_non_zero_c));

        R1cs {
            inputs,
            witness,
            field_max,
            constraints,
            non_zero_entries
        }
    }
}

// TESTS
fn run_e2e(circuit: &str, header: &str, witness: &str) {
    // Read files into buffers
    let mut fh = File::open(header).unwrap();
    let mut bufh = Vec::new();
    fh.read_to_end(&mut bufh).unwrap();
    let mut fcs = File::open(circuit).unwrap();
    let mut bufcs = Vec::new();
    fcs.read_to_end(&mut bufcs).unwrap();
    let mut fw = File::open(witness).unwrap();
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
    assert!(res.unwrap(), "should be satisfied");

    // Crypto proof public params
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

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
        .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
        .is_ok());
    println!("proof verification successful!");
}

#[test]
fn test_e2e_foo() {
    run_e2e("test/foo.zkif", "test/foo.inp.zkif", "test/foo.wit.zkif");
}


#[test]
fn test_e2e_add() {
    run_e2e("test/add.zkif", "test/add.inp.zkif", "test/add.wit.zkif");
}

#[test]
fn test_e2e_inv() {
    run_e2e("test/inv.zkif", "test/inv.inp.zkif", "test/inv.wit.zkif");
}
