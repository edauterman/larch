extern crate bellman_ce as bellman;
extern crate sapling_crypto_ce as sapling_crypto;

use bellman::{
    pairing::{ff::Field, Engine},
    ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use sapling_crypto::circuit::{
    boolean::{AllocatedBit, Boolean},
    sha256::sha256_compression_function,
    uint32::UInt32,
};

#[derive(Debug)]
pub struct BellmanR1CS<E: Engine> {
    pub aux_count: usize,
    pub constraints: Vec<BellmanConstraint<E>>,
}

impl<E: Engine> BellmanR1CS<E> {
    pub fn new() -> Self {
        BellmanR1CS {
            aux_count: 0,
            constraints: vec![],
        }
    }
}

#[derive(Debug)]
pub struct BellmanWitness<E: Engine> {
    pub values: Vec<E::Fr>,
}

#[derive(Debug, PartialEq)]
pub struct BellmanConstraint<E: Engine> {
    pub a: Vec<(usize, E::Fr)>,
    pub b: Vec<(usize, E::Fr)>,
    pub c: Vec<(usize, E::Fr)>,
}

fn sha256_round<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    input: &Vec<Option<E::Fr>>,
    current_hash: &Vec<Option<E::Fr>>,
) -> Result<(Vec<usize>, Vec<usize>, Vec<usize>), SynthesisError> {
    // Allocate bits for `input`
    let input_bits = input
        .iter()
        .enumerate()
        .map(|(index, i)| {
            AllocatedBit::alloc::<E, _>(
                &mut cs.namespace(|| format!("input_{}", index)),
                Some(*i == Some(<E::Fr as Field>::one())),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Define Booleans whose values are the defined bits
    let input = input_bits
        .iter()
        .map(|i| Boolean::Is(i.clone()))
        .collect::<Vec<_>>();

    // Allocate bits for `current_hash`
    let current_hash_bits = current_hash
        .iter()
        .enumerate()
        .map(|(index, i)| {
            AllocatedBit::alloc::<E, _>(
                &mut cs.namespace(|| format!("current_hash_{}", index)),
                Some(*i == Some(<E::Fr as Field>::one())),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Define Booleans whose values are the defined bits
    let current_hash = current_hash_bits
        .chunks(32)
        .map(|chunk| {
            UInt32::from_bits_be(
                &chunk
                    .into_iter()
                    .map(|i| Boolean::Is(i.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();

    // Apply the compression function, returning the 8 bytes of outputs
    let res = sha256_compression_function::<E, _>(&mut cs, &input, &current_hash).unwrap();

    // Extract the 256 bits of output out of the 8 bytes
    let output_bits = res
        .into_iter()
        .flat_map(|u| u.into_bits_be())
        .map(|b| b.get_variable().unwrap().clone())
        .collect::<Vec<_>>();

    // Return indices of `input`, `current_hash` and `output` in the CS
    Ok((
        input_bits
            .into_iter()
            .map(|b| var_to_index(b.get_variable()))
            .collect(),
        current_hash_bits
            .into_iter()
            .map(|b| var_to_index(b.get_variable()))
            .collect(),
        output_bits
            .into_iter()
            .map(|b| var_to_index(b.get_variable()))
            .collect(),
    ))
}

impl<E: Engine> ConstraintSystem<E> for BellmanWitness<E> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.values.len();
        let var = Variable::new_unchecked(Index::Aux(index));
        self.values.push(f().unwrap());
        Ok(var)
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        unreachable!("Bellman helpers are not allowed to allocate public variables")
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _: LA, _: LB, _: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        // do nothing
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // do nothing
    }

    fn pop_namespace(&mut self) {
        // do nothing
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

impl<E: Engine> ConstraintSystem<E> for BellmanR1CS<E> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        // we don't care about the value as we're only generating the CS
        let index = self.aux_count;
        let var = Variable::new_unchecked(Index::Aux(index));
        self.aux_count += 1;
        Ok(var)
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        unreachable!("Bellman helpers are not allowed to allocate public variables")
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        let a = a
            .as_ref()
            .into_iter()
            .map(|(variable, coefficient)| (var_to_index(*variable), *coefficient))
            .collect();
        let b = b
            .as_ref()
            .into_iter()
            .map(|(variable, coefficient)| (var_to_index(*variable), *coefficient))
            .collect();
        let c = c
            .as_ref()
            .into_iter()
            .map(|(variable, coefficient)| (var_to_index(*variable), *coefficient))
            .collect();

        self.constraints.push(BellmanConstraint { a, b, c });
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // do nothing
    }

    fn pop_namespace(&mut self) {
        // do nothing
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

pub fn generate_sha256_round_constraints<E: Engine>(
) -> (BellmanR1CS<E>, Vec<usize>, Vec<usize>, Vec<usize>) {
    let mut cs = BellmanR1CS::new();

    let (input_bits, current_hash_bits, output_bits) =
        sha256_round(&mut cs, &vec![None; 512], &vec![None; 256]).unwrap();

    // res is now the allocated bits for `input`, `current_hash` and `sha256_output`

    (cs, input_bits, current_hash_bits, output_bits)
}

pub fn generate_sha256_round_witness<E: Engine>(
    input: &[E::Fr],
    current_hash: &[E::Fr],
) -> Vec<E::Fr> {
    assert_eq!(input.len(), 512);
    assert_eq!(current_hash.len(), 256);

    let mut cs: BellmanWitness<E> = BellmanWitness {
        values: vec![<E::Fr as Field>::one()],
    };

    sha256_round(
        &mut cs,
        &input.iter().map(|x| Some(x.clone())).collect(),
        &current_hash.iter().map(|x| Some(x.clone())).collect(),
    )
    .unwrap();

    cs.values
}

fn var_to_index(v: Variable) -> usize {
    match v.get_unchecked() {
        Index::Aux(i) => i + 1,
        Index::Input(0) => 0,
        _ => unreachable!("No public variables should have been allocated"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellman::pairing::bn256::{Bn256, Fr};

    #[test]
    fn generate_constraints() {
        let (_c, input, current_hash, output) = generate_sha256_round_constraints::<Bn256>();
        assert_eq!(input.len(), 512);
        assert_eq!(current_hash.len(), 256);
        assert_eq!(output.len(), 256);
    }

    #[test]
    fn generate_witness() {
        let witness =
            generate_sha256_round_witness::<Bn256>(&vec![Fr::one(); 512], &vec![Fr::zero(); 256]);
        assert_eq!(witness.len(), 26935);
    }

    #[test]
    fn test_cs() {
        use sapling_crypto::circuit::test::TestConstraintSystem;

        let mut cs: TestConstraintSystem<Bn256> = TestConstraintSystem::new();

        let _ = sha256_round(
            &mut cs,
            &vec![Some(Fr::zero()); 512],
            &vec![Some(Fr::one()); 256],
        )
        .unwrap();

        assert!(cs.is_satisfied());
    }
}
