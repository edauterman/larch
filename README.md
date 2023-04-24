# Larch

Larch is an accountable authentication framework with strong security and privacy properties. Larch provides strong user privacy while ensuring that every authentication is correctly recorded by the larch log server. Specifically, an attacker that compromises a user’s device cannot authenticate without creating evidence in the log, and the log cannot learn which web service (relying party) the user is authenticating to. Larch is backwards-compatible with relying parties that support FIDO2, TOTP, and password-based login.

This implementation accompanies our paper "Accountable authentication with privacy protection: The Larch system for universal login" by Emma Dauterman, Danny Lin, Henry Corrigan-Gibbs, and David Mazieres.

**WARNING:** This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

This prototype is released under the Apache v2 license (see [License](https://github.com/edauterman/larch/LICENSE)).

## Setup

For our experiments, we will use a cluster of AWS EC2 instances. Reviewers should have been provided with credentials to our AWS environment with compute resources. Reviewers should also have moved `larch.pem` (provided with submission) to `~/.ssh/` and set permissions to 400.

[2 minutes] Make sure python3 is downloaded. Then run the following:
```
git clone https://github.com/edauterman/larch
cd larch/scripts
pip3 install -r requirements.txt
mkdir out_data
mkdir out_plots

```


### Building from source
Dependencies
* OpenSSL 1.1
* [gRPC](https://grpc.io/docs/languages/cpp/quickstart/)
* [emp-toolkit](https://github.com/emp-toolkit) (install in same directory where `larch/` is installed, make with options `ENABLE_THREADING` and `CRYPTO_IN_CIRCUIT`)
* [emp-ag2pc](https://github.com/emp-toolkit/emp-ag2pc) (install in same directory where `larch/` is installed, install `emp-ot` as part of dependencies)

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

