#!/bin/sh

# Usage:
#
# lws-ota-manifest.sh <path to binary update image> <path to siging private JWK> <x.com:/path/to/repo/serve/files>
#
# We take various measurements of the binary update into a JSON manifest, sign the
# manifest, then gzip the image and upload both to an http server.

# repo server base address for ssh
REPO=$3
JWK_PRIVKEY_PATH=$2

# the leaf part of the build dir path is the variant name
VAR=`pwd | sed "s/.*\///g" | sed "s/\\///g"`
UT=`date +%s`
size=`stat -c %s $1`
unixtime=`stat -c %Y $1`
gzimg=$VAR-$UT.img.gz

echo -n "{ \"variant\": \"$VAR\", \"path\": \"$gzimg\", \"size\": $size, \"unixtime\": $unixtime, \"sha512\": \"`sha512sum $1 | cut -d' ' -f1`\", \"reset\": true }" | lws-crypto-jws -s "ES512"  -k $2 2>/dev/null > .manifest.jws.1

cp $1 .image
rm -f .image.gz
gzip .image
scp .image.gz root@$REPO$VAR/$gzimg
scp .manifest.jws.1 root@$REPO$VAR/manifest.jws

