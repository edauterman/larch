#!/bin/bash
flatc -o outs schema/zkinterface.fbs --json --strict-json -- $1
filename="${1%.*}"
json="$filename".json
less outs/$json

