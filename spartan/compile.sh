cp circuits/log.code circuits/log_backup.code
ZoKrates/target/release/zokrates compile -i circuits/log.code -o circuits/log.out
cp circuits/log.code circuits/log.ir
cp circuits/log_backup.code circuits/log.code
