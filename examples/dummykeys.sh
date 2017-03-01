#!/bin/sh

set -eu

if ! which openssl >/dev/null 2>&1 ; then
    echo "openssl not found" >&2
    exit 1
fi

ca_sh=
for d in /usr/lib/ssl/misc /usr/local/lib/ssl/misc /usr/local/openssl/misc /usr/local/share/eopenssl/misc ; do
    if [ -x "${d}/CA.sh" ]; then
        ca_sh="${d}/CA.sh"
        break
    fi
    if [ -x "${d}/CA.pl" ]; then
        ca_sh="${d}/CA.pl"
        break
    fi
done

own_dir="$(dirname "$0")"
if which readlink >/dev/null 2>&1 ; then
    own_dir="$(readlink -f "$own_dir")"
    cd "$own_dir"
else
    cd "$own_dir"
    own_dir="$(pwd)"
fi

if [ -z "$ca_sh" ]; then
    echo "openssl's CA.sh not found" >&2
    exit 1
fi

mkdir -p certificates
cd certificates
"$ca_sh" -newca
openssl genrsa -out server.key 1024
openssl req -new -out server.req -key server.key
openssl ca -policy policy_anything -days 31 -out server.pem -infiles server.req
exit 0
