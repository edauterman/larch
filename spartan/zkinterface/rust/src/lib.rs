//! # zkInterface, a standard tool for zero-knowledge interoperability
//!
//! zkInterface is a standard tool for zero-knowledge interoperability between different ZK DSLs, gadget libraries, and proving systems.
//! The zkInterface project was born in the [ZKProof](https://zkproof.org/) community.
//!
//! ## Introduction
//!
//! ![alt text](https://qedit.s3.eu-central-1.amazonaws.com/pictures/zkinterface.png)
//!
//! *zkInterface* is specification and associated tools for enabling interoperability between implementations of general-purpose zero-knowledge proof systems. It aims to facilitate interoperability between zero knowledge proof implementations, at the level of the low-constraint systems that represent the statements to be proven. Such constraint systems are generated by _frontends_ (e.g., by compilation from higher-level specifications), and are consumed by cryptographic _backends_ which generate and verify the proofs. The goal is to enable decoupling of frontends from backends, allowing application writers to choose the frontend most convenient for their functional and development needs and combine it with the backend that best matches their performance and security needs.
//!
//! The standard specifies the protocol for communicating constraint systems, for communicating variable assignments (for production of proofs), and for constructing constraint systems out of smaller building blocks (_gadgets_). These are specified using language-agnostic calling conventions and formats, to enable interoperability between different authors, frameworks and languages.
//! A simple special case is monolithic representation of a whole constraint system and its variable assignments. However, there are a need for more richer and more nuanced forms of interoperability:
//!
//! * Precisely-specified statement semantics, variable representation and variable mapping
//! * Witness reduction, from high-level witnesses to variable assignments
//! * Gadgets interoperability, allowing components of constraint systems to be packaged in reusable and interoperable form
//! * Procedural interoperability, allowing execution of complex code to facilitate the above
//!
//! # Examples
//!
//! zkInterface does not force a serialization method, it should be provided by the user - `serialize_small()` in this example.
//!
//! Create a `CircuitHeader`
//!
//! ```
//! use zkinterface::producers::examples::{serialize_small, NEG_ONE};
//! use zkinterface::KeyValue;
//!
//! let (x,y,zz) = (3,4,25);
//!
//! // variables ids 1,2 and 3 are used as instances variables
//! let header = zkinterface::CircuitHeader {
//!         instance_variables: zkinterface::Variables {
//!            variable_ids: vec![1, 2, 3],  // x, y, zz
//!            values: Some(serialize_small(&[x, y, zz])),
//!        },
//!        free_variable_id: 6,
//!        field_maximum: Some(serialize_small(&[NEG_ONE])),
//!        configuration: Some(vec![
//!             KeyValue::from(("Name", "example")),
//!         ]),
//!    };
//! ```
//!
//! Create a Circuit Header
//!
//! ```
//! let (x,y) = (3,4);
//!
//! use zkinterface::producers::examples::serialize_small;
//!
//! //variables ids 4 and 5 are used as witness variables
//! let witness = zkinterface::Witness {
//!         assigned_variables: zkinterface::Variables {
//!             variable_ids: vec![4, 5], // xx, yy
//!             values: Some(serialize_small(&[
//!                 x * x, // var_4 = xx = x^2
//!                 y * y, // var_5 = yy = y^2
//!             ])),
//!        }
//!    };
//! ```
//!
//! Create a `ConstraintSystem` from an R1CS vector
//!
//! ```
//! let constraints_vec: &[((Vec<u64>, Vec<u8>), (Vec<u64>, Vec<u8>), (Vec<u64>, Vec<u8>))] = &[
//!     // (A ids values)  *  (B ids values)  =  (C ids values)
//!     ((vec![1], vec![1]), (vec![1], vec![1]), (vec![4], vec![1])), // x * x = xx
//!     ((vec![2], vec![1]), (vec![2], vec![1]), (vec![5], vec![1])), // y * y = yy
//!     ((vec![0], vec![1]), (vec![4, 5], vec![1, 1]), (vec![3], vec![1])), // 1 * (xx + yy) = z
//! ];
//!
//! let constraints = zkinterface::ConstraintSystem::from(constraints_vec);
//! ```
//!
//! ## The Statement Builder
//!
//! zkInterface provides a `StatementBuilder` to assists with constructing and storing a statement in zkInterface format.
//!
//!```
//! use zkinterface::{StatementBuilder, Sink, WorkspaceSink, CircuitHeader, ConstraintSystem, Witness};
//!
//! // Create a workspace where to write zkInterafce files.
//! let sink = WorkspaceSink::new("local/test_builder").unwrap();
//! let mut builder = StatementBuilder::new(sink);
//!
//! // Use variables, construct a constraint system, and a witness.
//! let var_ids = builder.allocate_vars(3);
//! let cs = ConstraintSystem::default();
//! let witness = Witness::default();
//!
//! builder.finish_header().unwrap();
//! builder.push_witness(witness).unwrap();
//! builder.push_constraints(cs).unwrap();
//!```
//!
//! ## The Simulator
//!
//! zkInterface provides a Simulator to check entire constraint system and output what constraints are violated, if any.
//!
//!```
//! # use zkinterface::producers::examples::{example_circuit_header, example_witness, example_constraints};
//! use zkinterface::consumers::simulator::Simulator;
//!
//! pub fn simulate() -> zkinterface::Result<()> {
//!   let header = example_circuit_header();
//!   let witness = example_witness();
//!   let cs = example_constraints();
//!
//!   let mut simulator = Simulator::default();
//!   simulator.ingest_header(&header)?;
//!   simulator.ingest_witness(&witness)?;
//!   simulator.ingest_constraint_system(&cs)?;
//!   Ok(())
//! }
//!```
//!
//! ## The Validator
//!
//! zkInterface provides a Validator to check the syntax and the semantics of the provided parameters and return a list of violations, if any.
//!
//!```
//! # use zkinterface::producers::examples::{example_circuit_header, example_witness, example_constraints};
//! use zkinterface::consumers::validator::Validator;
//!
//! let header = example_circuit_header();
//! let witness = example_witness();
//! let constraints = example_constraints();
//!
//! let mut validator = Validator::new_as_prover();
//! validator.ingest_header(&header);
//! validator.ingest_witness(&witness);
//! validator.ingest_constraint_system(&constraints);
//!
//! let violations = validator.get_violations();
//! if violations.len() > 0 {
//!       eprintln!("Violations:\n- {}\n", violations.join("\n- "));
//! }
//!```
//!
//! In addition to the library, a CLI tool is provided. The CLI tool can execute the following commands:
//! - `zkif example`     Create example statements.
//! - `zkif cat`         Write .zkif files to stdout.
//! - `zkif to-json`     Convert to JSON on a single line.
//! - `zkif to-yaml`     Convert to YAML.
//! - `zkif explain`     Print the content in a human-readable form.
//! - `zkif validate`    Validate the format and semantics of a statement, as seen by a verifier.
//! - `zkif simulate`    Simulate a proving system as prover by verifying that the statement is true.
//! - `zkif stats`       Calculate statistics about the circuit.
//! - `zkif clean`       Clean workspace by deleting all *.zkif files in it.

#[allow(unused_imports)]
/// All CLI related logic.
pub mod cli;

/// Various zkInterface consumers including: validator, simulator, stats, reader and a workspace
pub mod consumers;

/// Various zkInterface producers including: examples, builder, gadget_caller and workspace
pub mod producers;

/// Fully-owned version of each data structure
/// These structures may be easier to work with than the no-copy versions found in zkinterface_generated and Reader
pub mod structs;

/// Automatically generated by the FlatBuffers compiler
#[allow(unused_imports)]
pub mod zkinterface_generated;

#[doc(hidden)]
pub extern crate flatbuffers;
pub extern crate serde;
pub use consumers::{
    reader::Reader,
    workspace::Workspace,
};
pub use producers::{
    builder::{Sink, StatementBuilder},
    workspace::{WorkspaceSink, clean_workspace},
};
pub use structs::{
    header::CircuitHeader,
    command::Command,
    constraints::{ConstraintSystem, BilinearConstraint},
    keyvalue::KeyValue,
    message::Message,
    messages::Messages,
    variables::Variables,
    witness::Witness,
};

// Common definitions.
use std::error::Error;

/// A result type with a predefined error type
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;