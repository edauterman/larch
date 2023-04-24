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
These scripts will run experiments for FIDO2, TOTP, and password-based login respectively and output measurements to `larch/scripts/out_data`. The reference data files that we generates are included in `larch/scripts/ref_data` for comparison.

## Plot figures

We now describe how to generate the figures and tables in the paper. For comparison, we include the reference plots we generated in `larch/scripts/ref_plots`, and we also link them below.

### Process experiment data (before generating any plots)

Process the experiment data by running:
```
python3 process_all_exp.py
```
This script will generate `larch/scripts/out_data/perf.json`, which gathers the performance numbers from various scripts and (for TOTP) averages across multiple executions.

### Figure 3 (left)

Generate the left plot in figure 3 by running:
```
python3 plot_fido2.py
```
This script will output a plot in `larch/scripts/out_plots/plot_fido2.png`.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_fido2.png" width="400">

### Figure 3 (center)

Generate the center plot in figure 3 by running:
```
python3 plot_pw.py
```
This script will output a plot in `larch/scripts/out_plots/plot_pw.png`.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_pw.png" width="400">


### Figure 3 (right)

Generate the right plot in figure 3 by running:
```
python3 plot_totp.py
```
This script will output a plot in `larch/scripts/out_plots/plot_totp.png`.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_totp.png" width="400">

### Figure 4 (left)

Generate the left plot in figure 4 by running:
```
python3 plot_storage.py
```
This script will output a plot in `larch/scripts/out_plots/plot_storage.png`. This plot is purely analytical and not based on any performance measurements.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_storage.png" width="400">

### Figure 4 (right)

Generate the right plot in figure 4 by running:
```
python3 plot_cost.py
```
This script will output a plot in `larch/scripts/out_plots/plot_cost.png`.

Note that this figure looks slightly different than the figure in the submission draft. This is due to a bug in the script. We include a corrected figure below.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_cost.png" width="400">

### Figure 5

Generate the right plot in figure 4 by running:
```
python3 plot_pw_comm.py
```
This script will output a plot in `larch/scripts/out_plots/plot_pw_comm.png`. This plot is purely analytical and not based on any performance measurements.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_pw_comm.png" width="400">

### Table 6 

Output the data in table 6 by running:
```
python3 print_table.py
```

```
╒════════════════════════╤═══════════╤══════════════╤═══════════╕
│                        │     FIDO2 │         TOTP │        PW │
╞════════════════════════╪═══════════╪══════════════╪═══════════╡
│ Online time (ms)       │  150.07   │    73        │  73       │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ Total time (ms)        │  150.07   │  1165        │  73       │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ Online comm (KiB)      │ 1770.75   │   201.46     │   3.25195 │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ Total comm (KiB)       │ 1770.75   │ 66492        │   3.25195 │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ Auth record (B)        │   88      │    88        │ 138       │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ Log presig (B)         │  192      │     0        │   0       │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ Auths/core/s           │    6.2    │     0.879507 │  47.619   │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ 10M auths min cost ($) │   19.1455 │ 18040.6      │   2.47917 │
├────────────────────────┼───────────┼──────────────┼───────────┤
│ 10M auths max cost ($) │   38.2702 │ 32500        │   4.95833 │
╘════════════════════════╧═══════════╧══════════════╧═══════════╛
```

## Limitations

Our larch implementation is a research prototype and so has several limitations. A real-world deployment of larch would require TLS and require the user to authenticate to the log on every interaction (we do not implement this). We also do not implement retrieving log entries (we simply validate and store the ciphertext and corresponding signatures). For FIDO2, we generate many presignatures, but do not implement the mechanism for refreshing presignatures after these presignatures have been exhausted, and we do not implement using the slower multisignature protocol in the event that new presignatures cannot be established. For TOTP, our implementation currently takes the number of relying parties at compilation time. Our FIDO2 extension is a proof-of-concept to show compatability and not highly optimized.

## Building from source

If you use the ec2 image, you do not need to build from source. If you want to build from source, install the following dependencies:
* OpenSSL 1.1
* [gRPC](https://grpc.io/docs/languages/cpp/quickstart/)
* [emp-toolkit](https://github.com/emp-toolkit) (install in same directory where `larch/` is installed, make with options `ENABLE_THREADING` and `CRYPTO_IN_CIRCUIT`)
* [emp-ag2pc](https://github.com/emp-toolkit/emp-ag2pc) (install in same directory where `larch/` is installed, install `emp-ot` as part of dependencies)

If you're planning to run the browser extension:
* Make an `out/` directory.
* In `src/config.h`, set `OUT_DIR` to the location of the `out/` directory and `PROJ_DIR` to the location of `larch/`.
* Set `LOG_IP_ADDR` to the public IP address of the log (with the port number), and `LOG_BIND_ADDR` to `0.0.0.0:PORT_NUM`.

Build larch with FIDO2 and password-based login:
```
cd network
cmake .
make
cd ..
cmake .
make
```

Build larch with TOTP:
```
cd totp/network
cmake .
make
cd ..
cmake .
make
```

### Run larch with FIDO2 manually

Start log as
```
./build/bin/log
```

Run authentication benchmarks from the client:
```
./build/bin/auth_bench <log_ip_addr> <output-perf-file>
```

### Run larch with TOTP manually

Start log as
```
./totp/bin/serverNN
```
where NN is the number of keys supported by the client.

To register and authenticate:
```
# clientNN-init <server ip> <key_index1>:<totp_secret1> <key_index2>:<totp_secret2> ...
# Initializes client and registers the given keys.
# all key_index:secret pairs is optional; none are required.
# key indices start at 0.
bin/clientNN-init 127.0.0.1 4:JBSWY3DPEHPK3PXP

# clientNN-auth <server ip> <key_index>
bin/clientNN-auth 127.0.0.1 4
```

### Run larch with passwords manually

Start log as
```
./build/bin/pw_log
```

Run authentication benchmarks from the client:
```
./build/bin/pw_latency_bench
```

### Set up the web extension for FIDO2

Make an `out/` directory.

In `src/config.h`, set `OUT_DIR` to the location of the `out/` directory and `PROJ_DIR` to the location of `larch/`.

Set `LOG_IP_ADDR` to the public IP address of the log (with the port number), and `LOG_BIND_ADDR` to `0.0.0.0:PORT_NUM`.

Build (following instructions above).

Edit `manifest.json` so that `path` points to executable `build/bin/agent`. Move `manifest.json` to XXX (necessary for Chrome to give the `agent` executable the necessary permissions to be invoked by the browser extension).

Load the browser extension in Chrome.

Start the log by running
```
./build/bin/log
```

Initialize the state of the agent by running from the command line
```
./build/bin/init
```

The web extension is not compatible with FIDO2 relying parties that require attestation certificates (for relying parties that permit self-signed certificates, this can be easily fixed by generating a self-signed certificate). You can test the web extension [here](https://webauthn.io/).

