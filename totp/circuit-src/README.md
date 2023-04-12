# Circuit

This is the source code for the TOTP multi-party computation circuit.

## Build

The [CBMC-GC-2](https://gitlab.com/securityengineering/CBMC-GC-2) compiler must be installed and in your PATH.

Run `build-final.sh` to build circuits of sizes 20, 40, 60, 80, and 100. Sizes can be adjusted in the script.

## Acknowledgements

- SHA-1 primitive: GPL v2. Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
- SHA-256 primitive: Brad Conte (brad AT bradconte.com)
- ChaCha20 primitive was implemented from scratch.
