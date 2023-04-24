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

## Run experiments

Run the following experiments sequentially in `larch/scripts`:
```
python3 exp_fido2.py
python3 exp_totp.py
python3 exp_pw.py
```
These scripts will run experiments for FIDO2, TOTP, and password-based login respectively and output measurements to `larch/scripts/out_data`. 

## Plot figures

Process the experiment data by running:
```
python3 process_all_exp.py
```
This script will generate `larch/scripts/out_data/perf.json`, which gathers the performance numbers from various scripts.

### Figure 3 (left)

Generate the left plot in figure 3 by running:
```
python3 plot_fido2.py
```

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_fido2.pdf" width="400">

### Figure 3 (center)

Generate the center plot in figure 3 by running:
```
python3 plot_pw.py
```

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_pw.pdf" width="400">


### Figure 3 (right)

Generate the right plot in figure 3 by running:
```
python3 plot_totp.py
```

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_totp.pdf" width="400">

### Figure 4 (left)

Generate the left plot in figure 4 by running:
```
python3 plot_storage.py
```
This plot is purely analytical and not based on any performance measurements.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_storage.pdf" width="400">

### Figure 4 (right)

Generate the right plot in figure 4 by running:
```
python3 plot_cost.py
```

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_cost.pdf" width="400">

TODO note bug that causes to look different from paper

### Figure 5

Generate the right plot in figure 4 by running:
```
python3 plot_pw_comm.py
```
This plot is purely analytical and not based on any performance measurements.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_pw_comm.pdf" width="400">

### Table 6 

Output the data in table 6 by running:
```
python3 print_table.py
```

```
╒════════════════════════╤════════════╤══════════════╤═══════════╕
│                        │      FIDO2 │         TOTP │        PW │
╞════════════════════════╪════════════╪══════════════╪═══════════╡
│ Online time (ms)       │  148.74    │    73        │  73       │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Total time (ms)        │  148.74    │  1176        │  73       │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Online comm (KiB)      │ 1770.75    │   201.009    │   3.25195 │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Total comm (KiB)       │ 1770.75    │ 66486.9      │   3.25195 │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Auth record (B)        │   88       │    88        │ 138       │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Log presig (B)         │  192       │     0        │   0       │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Auths/core/s           │   16.4667  │     0.856164 │  47.619   │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ 10M auths min cost ($) │    7.27366 │ 18041.6      │   2.47917 │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ 10M auths max cost ($) │   14.5265  │ 32502.4      │   4.95833 │
╘════════════════════════╧════════════╧══════════════╧═══════════╛
```
TODO update this with correct numbers


## Building from source
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

