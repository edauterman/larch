# Larch TOTP

This implements the TOTP part of Larch using [emp-ag2pc](https://github.com/emp-toolkit/emp-ag2pc) for secure multi-party computation.

Circuit source code is in [circuit-src/](./circuit-src/).

## Build

Prerequisites: emp-tool, emp-ot, emp-ag2pc, gRPC, protobuf compiler

```bash
cmake . -DCMAKE_BUILD_TYPE=Release
make -j8
```

If you have the dependencies installed at non-standard locations:

```bash
cmake . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$HOME/code/crypto/prefix-emptool-host \
    -DCMAKE_PREFIX_PATH=$HOME/code/crypto/prefix-emptool-host \
    -DCMAKE_FOLDER=$HOME/code/crypto/prefix-emptool-host \
    -DEMP-TOOL_INCLUDE_DIRS=$HOME/code/crypto/prefix-emptool-host/include
make -j8
```

## Test

There are 3 executables for each circuit variant:

- clientNN-init
- clientNN-auth
- serverNN

where `NN` is the number of keys supported by the circuit.

To run the server:

```bash
bin/serverNN
```

To register and authenticate:

```bash
# clientNN-init <server ip> <key_index1>:<totp_secret1> <key_index2>:<totp_secret2> ...
# Initializes client and registers the given keys.
# all key_index:secret pairs is optional; none are required.
# key indices start at 0.
bin/clientNN-init 127.0.0.1 4:JBSWY3DPEHPK3PXP

# clientNN-auth <server ip> <key_index>
bin/clientNN-auth 127.0.0.1 4
```

The server uses TCP port `44400 + NN` for gRPC and `44400 + NN + 1` for MPC, so multiple key counts can be used simultaneously.
