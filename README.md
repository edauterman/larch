# Larch

Larch is an accountable authentication framework with strong security and privacy properties. Larch is backwards-compatible with relying parties that support FIDO2, TOTP, and password-based login.

This implementation accompanies our paper "Accountable authentication with privacy protection: The Larch system for universal login" by Emma Dauterman, Danny Lin, Henry Corrigan-Gibbs, and David Mazieres.

**WARNING:** This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

This prototype is released under the Apache v2 license (see [License](https://github.com/edauterman/larch/LICENSE)).

## Setup

For our experiments, we will use a cluster of AWS EC2 instances. Reviewers should have been provided with credentials to our AWS environment with compute resources to set the environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. Reviewers should also have moved `larch.pem` (provided with submission) to `~/.ssh/` and set permissions to 400.

[2 minutes] Make sure python3 is downloaded. Then run the following:
```
git clone https://github.com/edauterman/larch
cd larch/scripts
pip3 install -r requirements.txt
mkdir out_data
mkdir out_plots
```

## Getting started

After running the setup instructions above, you can test that everything is set up by running the following:
```
cd scripts
python3 exp_pw.py       # 6 min
```
This runs the password-based login experiments, which are the fastest to run. The script launches 2 ec2 instances, 1 client and 1 log server, and then terminates the instances at the end of the experiment.

You can verify that the outputs are correctly logged in `scripts/out_data/pw_exp` (there should be 2 files, `out` and `out_1`). 

From these files, you can generate the center plot in Figure 3 by running
```
python3 plot_pw.py      # < 1 min
```
which outputs a plot at `scripts/out_plots/plot_pw.png`.

The plot should look roughly like this:

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_pw.png" width="400">

## Run all experiments

Run the following experiments sequentially in `scripts`:
```
cd scripts
python3 exp_fido2.py    # 14 min 
python3 exp_totp.py     # 12 min
python3 exp_pw.py       # 6 min
```
These scripts will run experiments for FIDO2, TOTP, and password-based login respectively and output measurements to `scripts/out_data`. The reference data files that we generated are included in `scripts/ref_data` for comparison.

Each experiment launches 2 EC2 instances, 1 client and 1 log server, in `us-east-2` and terminates the instances at the end of the experiment. If you interrupt an experiment (e.g. CTRL-C), please check the ec2 console to make sure that the instances are properly terminated.

Note: If you change the instance sizes or parameter settings (i.e. number of clients and number of presignatures) for the throughput experiment in `exp_fido2.py`, it is possible that the log server could run out of memory under high client load (if this happens, you will see error messages from the clients). The throughput experiment settings in our scripts are configured to minimize the likelihood of this happening (although we use a small server instance, so there is still some small chance of this happening). If you see this happen, restart the script and consider adjusting parameter settings. A real-world deployment would drop requests if it was ever under load that it could not handle.

## Plot figures

We now describe how to generate the figures and tables in the paper. The plots are generated in `scripts/out_plots`. For comparison, we include the reference plots we generated in `scripts/ref_plots`, and we also link them below.

### Process experiment data (before generating any plots)

Process the experiment data by running in `scripts/`:
```
python3 process_all_exp.py  # < 1 min
```
This script will generate `scripts/out_data/perf.json`, which gathers the performance numbers from various scripts and (for TOTP) averages across multiple executions. (For FIDO2 and password-based login, the averaging is done within the individual experiments.)

### Figure 3 (left)

Generate the left plot in figure 3 by running in `scripts/`:
```
python3 plot_fido2.py       # < 1 min
```
This script will output a plot in `scripts/out_plots/plot_fido2.png`.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_fido2.png" width="400">

### Figure 3 (center)

Generate the center plot in figure 3 by running in `scripts/`
```
python3 plot_pw.py          # < 1 min
```
This script will output a plot in `scripts/out_plots/plot_pw.png`.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_pw.png" width="400">


### Figure 3 (right)

Generate the right plot in figure 3 by running in `scripts/`:
```
python3 plot_totp.py        # < 1 min
```
This script will output a plot in `scripts/out_plots/plot_totp.png`.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_totp.png" width="400">

### Figure 4 (left)

Generate the left plot in figure 4 by running in `scripts/`:
```
python3 plot_storage.py     # < 1 min
```
This script will output a plot in `scripts/out_plots/plot_storage.png`. This plot is purely analytical (based on presignature size from our ECDSA multisignature protocol) and not based on any performance measurements.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_storage.png" width="400">

### Figure 4 (right)

Generate the right plot in figure 4 by running in `scripts/`:
```
python3 plot_cost.py        # < 1 min
```
This script will output a plot in `scripts/out_plots/plot_cost.png`.

Note that this figure looks slightly different than the figure in the submission draft. This is due to a bug in the script that we fixed since submission time. We include a corrected figure below.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_cost.png" width="400">

### Figure 5

Generate the figure 5 plot by running in `scripts/`:
```
python3 plot_pw_comm.py     # < 1 min
```
This script will output a plot in `scripts/out_plots/plot_pw_comm.png`. This plot is purely analytical (based on the size of the cryptographic proof) and not based on any performance measurements.

<img src="https://github.com/edauterman/larch/blob/main/scripts/ref_plots/plot_pw_comm.png" width="400">

### Table 6 

Output the data in table 6 by running in `scripts/`:
```
python3 print_table.py      # < 1 min
```

We include a reference table below.
```
╒════════════════════════╤════════════╤══════════════╤═══════════╕
│                        │      FIDO2 │         TOTP │        PW │
╞════════════════════════╪════════════╪══════════════╪═══════════╡
│ Online time (ms)       │  150.85    │    73        │  75.2     │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Total time (ms)        │  150.85    │  1152.2      │  75.2     │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Online comm (KiB)      │ 1770.75    │   200.972    │   3.25195 │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Total comm (KiB)       │ 1770.75    │ 66485.3      │   3.25195 │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Auth record (B)        │   88       │    88        │ 138       │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Log presig (B)         │  192       │     0        │   0       │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ Auths/core/s           │    5.88333 │     0.869263 │  47.619   │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ 10M auths min cost ($) │   20.1704  │ 18037        │   2.47917 │
├────────────────────────┼────────────┼──────────────┼───────────┤
│ 10M auths max cost ($) │   40.32    │ 32493.8      │   4.95833 │
╘════════════════════════╧════════════╧══════════════╧═══════════╛
```

## Limitations

Our larch implementation is a research prototype and so has several limitations. A real-world deployment of larch would require TLS and require the user to authenticate to the log on every interaction (we do not implement this). We also do not implement retrieving log entries (we simply validate and store the ciphertext and corresponding signatures). For FIDO2, we generate many presignatures, but do not implement the mechanism for refreshing presignatures after these presignatures have been exhausted, and we do not implement using the slower multisignature protocol in the event that new presignatures cannot be established. For TOTP, our implementation currently takes the number of relying parties at compilation time. Our FIDO2 Chrome extension is a proof-of-concept to show compatability and not optimized.

## Building from source

If you use the ec2 image, you do not need to build from source (the below steps are not necessary for reproducing results if you follow the instructions above). If you want to build from source, install the following dependencies:
* OpenSSL 1.1
* [gRPC](https://grpc.io/docs/languages/cpp/quickstart/) and protoc plugin
* [emp-toolkit](https://github.com/emp-toolkit) (install in same directory where `larch/` is installed, make with options `ENABLE_THREADING` and `CRYPTO_IN_CIRCUIT`)
* [emp-ot](https://github.com/emp-toolkit/emp-ot) (install in same directory where `larch/` is installed)
* [emp-ag2pc](https://github.com/emp-toolkit/emp-ag2pc) (install in same directory where `larch/` is installed)

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

This uses a prebuilt TOTP circuit. To build the circuit from source, see [circuit-src](totp/circuit-src/README.md).

Building in release mode (`-DCMAKE_BUILD_TYPE=Release`) may be necessary to match our performance results.

### Run larch with FIDO2 manually

Start log as
```
./build/bin/log
```

Run authentication benchmarks from the client:
```
./build/bin/auth_bench <log_ip_addr> <output_perf_file>
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
./build/bin/pw_latency_bench <log_ip_addr> <output_perf_file>
```

### Set up the web extension for FIDO2

Make an `out/` directory.

In `src/config.h`, set `OUT_DIR` to the location of the `out/` directory and `PROJ_DIR` to the location of `larch/`.

Set `LOG_IP_ADDR` to the public IP address of the log (with the port number), and `LOG_BIND_ADDR` to `0.0.0.0:PORT_NUM`.

Build (following instructions above).

Edit `manifest.json` so that `path` points to executable `build/bin/agent`. 

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

## Acknowledgements

Our Chrome extension is based heavily on [kr-u2f](https://github.com/kryptco/kr-u2f).

Our AWS EC2 scripts are based on scripts from Natacha Crooks.

Our TOTP circuit includes the following implementations of crypto primitives:

- SHA-1: GPL v2. Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
- SHA-256 primitive: Brad Conte (brad AT bradconte.com)
