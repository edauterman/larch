ZoKrates/target/release/zokrates setup -i circuits/log.out -s zkinterface -p circuits/log.constraints
ZoKrates/target/release/zokrates generate-proof -i circuits/log.out -s zkinterface -w circuits/log.witness -j circuits/log.pubinputs -p circuits/log.privinputs
