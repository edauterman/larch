# Larch

### Setup
Dependencies
* OpenSSL 1.1
* [gRPC](https://grpc.io/docs/languages/cpp/quickstart/)
* [emp-toolkit](https://github.com/emp-toolkit) (install in same directory where `larch/` is installed)

Make an `out/` directory.

In `src/config.h`, set `OUT_DIR` to the location of the `out/` directory and `PROJ_DIR` to the location of `larch/`.
Set `LOG_IP_ADDR` to the public IP address of the log (with the port number), and `LOG_BIND_ADDR` to `0.0.0.0:PORT_NUM`.

```
cd network
cmake .
make
cd ..
cmake .
make
```

### Run log:
```
./build/bin/log [sigs]
```
If `sigs` is included, omit the ZK proof verification (used to benchmark signing time).

### Client tests/benchmarks:
* `client/bench/init`: Run to initialize state with log (log server should be running).
* `client/bench/sigs_bench`: Benchmark online signing time (log server should be running with only signature flag, init already run).
* `client/bench/auth_bench`: Benchmark end-to-end authentication time (log server should be running).
* `client/bench/throughput_bench`: Measures throughput (log server should be running, do not need to run init before).
* `client/bench/baseline_bench`: Measure baseline authentication time (do NOT need to run log server).
* `client/bench/agent`: Executable invoked by Chrome extension to handle webauthn requests.

### ZKBoo tests/benchmarks:
* `zkboo/test/ct_test`: Check that proof verifies correctly.
* `zkboo/test/serialize_test`: Check that proof serialization is correct.
* `zkboo/test/parallel_test`: Benchmark proof with correct number of repetitions.
TODO: write test to explicitly check for bad proofs.


### TODOs before open source
* Either get OpenSSL ECDSA signing working with correct signature format / correct OpenSSL
version or do more extensive testing for ECDSA sign/verify functions (for authenticating
ciphertexts sent to log and baseline).
* Make sure always fully propagating errors instead of just printing error
* More comprehensive testing (esp. for ZKBoo proofs when different types of errors introduced)
