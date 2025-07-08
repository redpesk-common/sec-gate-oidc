#!/bin/sh
# 
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

ok=:
for x in devel-key.pem devel-cert.pem; do
  if test -f $x; then
    echo "error the file $x already exist"
    ok=false
  fi
done
$ok || exit

# comment or modify the below line to enter real data
SUBJ="-subj /C=Fr/ST=Breizh/L=Lorient/O=IoT.bzh/OU=R&D/CN=oidc/emailAddress=fulup@hostname"

# set the duration of the certificates in days
DAYS=50

ext=$(mktemp)

cat > $ext << EOC
[default]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
EOC

openssl genpkey \
	-algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
	-outform PEM \
	-out devel-key.pem
openssl req -new \
	-key devel-key.pem \
	$SUBJ |
openssl x509 -req \
        -sha256 \
	-days $DAYS \
	-signkey devel-key.pem \
	-extfile $ext \
	-extensions default \
	-out devel-cert.pem 

rm $ext 
