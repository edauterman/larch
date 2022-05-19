RUSTFLAGS="-C target_cpu=native" cargo +nightly build --release
for name in $(cat ~/zkif/benchmarks.txt); do
  ./target/release/spzk verify --nizk ~/zkif/$name.mps.c.zkif ~/zkif/$name.mps.c.inp.zkif ~/zkif/$name.mps.c.wit.zkif 2>&1 | tee -a output.log &
done
wait
