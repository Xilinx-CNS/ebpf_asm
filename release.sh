#!/bin/sh

set -e

# Run the regression tests to ensure the release is good
./regression.py

vers=`git describe --tags`

reld="ebpf_asm-$vers"
mkdir "$reld"

sed -e "/VERSION =/cVERSION = '$vers'" < ebpf_asm.py > "$reld/ebpf_asm.py"
chmod +x "$reld/ebpf_asm.py"
cp README.md *.i regression.py paren.py "$reld/"
