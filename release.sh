#!/bin/sh

set -e

vers=`git describe --tags`

reld="ebpf_asm-$vers"
mkdir "$reld"

sed -e "/VERSION =/cVERSION = '$vers'" < ebpf_asm.py > "$reld/ebpf_asm.py"
chmod +x "$reld/ebpf_asm.py"
cp README *.i "$reld/"
