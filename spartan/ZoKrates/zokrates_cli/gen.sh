../target/release/zokrates setup -i emma_tmp/factorization.out -s zkinterface -p emma_tmp/factorization.constraints
../target/release/zokrates generate-proof -i emma_tmp/factorization.out -s zkinterface -w emma_tmp/factorization.witness -j emma_tmp/factorization.pubinputs -p emma_tmp/factorization.privinputs
