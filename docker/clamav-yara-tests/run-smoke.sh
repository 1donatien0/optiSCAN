#!/bin/sh
set -eu

echo "== ClamAV =="
clamscan --version
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' > /tmp/eicar.com
clamscan /tmp/eicar.com && exit 1 || true

echo "== YARA =="
yara --version
printf 'rule eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }\n' > /tmp/eicar.yar
yara /tmp/eicar.yar /tmp/eicar.com

echo "Smoke tests OK"
