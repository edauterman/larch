cp circuits/log.zok circuits/log_backup.zok
zokrates compile -i circuits/log.zok -o circuits/log.out
cp circuits/log.zok circuits/log.ir
cp circuits/log_backup.zok circuits/log.zok
zokrates compute-witness -i circuits/log.out -o circuits/log.witness -a 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
#zokrates compute-witness -i circuits/log.out -o circuits/log.witness
