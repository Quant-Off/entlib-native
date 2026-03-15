#!/bin/bash
set -euo pipefail

cargo +nightly build --release -p entlib-native-constant-time --bench dudect_audit

BIN=$(find ./target/release/deps/ -maxdepth 1 -type f -name "dudect_audit-*" -perm +111 | head -n 1)

OUT=$("$BIN")
echo "$OUT"

FAIL=0

echo "$OUT" | awk -F'max t = ' '/max t =/ {
    split($2,a,",")
    t=a[1]+0
    if (t<0) t=-t
    if (t>=4.5) {
        printf("FAIL: |max t| = %f >= 4.5\n", t)
        exit 1
    } else {
        printf("PASS: |max t| = %f < 4.5\n", t)
    }
}
'