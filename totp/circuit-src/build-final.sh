#!/usr/bin/env bash

set -eo pipefail

#sizes=(4 16 64 256 1024)
sizes=(20 40 60 80 100)
#sizes=(20)

cd "$(dirname "$0")"

for size in ${sizes[@]}
do
    (
        mkdir -p cbuilds/totp$size
        # optimization gets stuck if the time limit is too high, so use a timeout
#        timeout 6.3h cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 21600 --outdir cbuilds/totp$size --smt2 --z3 ||
#        timeout 3.3h cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 10800 --outdir cbuilds/totp$size --smt2 --z3 ||
#            timeout 2.3h cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 7200 --outdir cbuilds/totp$size --smt2 --z3 ||
#            timeout 1.3h cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 3600 --outdir cbuilds/totp$size --smt2 --z3 ||
#            timeout 45m cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 1800 --outdir cbuilds/totp$size --smt2 --z3 ||
            timeout 15m cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 600 --outdir cbuilds/totp$size --smt2 --z3 ||
            timeout 10m cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 300 --outdir cbuilds/totp$size --smt2 --z3 ||
            timeout 5m cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 120 --outdir cbuilds/totp$size --smt2 --z3 ||
            echo "[FAILED_BUILD] $size"
        # cbmc-gc totp_enc.c -DMAX_KEYS=$size --unwind 85 --minimization-time-limit 120 --outdir cbuilds/totp$size --smt2 --z3

        pushd cbuilds/totp$size
        circuit-utils --remove-or-gates --as-bristol bristol.txt
        popd

        cp cbuilds/totp$size/bristol.txt ../circuits/totp$size.txt
    ) &
done

wait
