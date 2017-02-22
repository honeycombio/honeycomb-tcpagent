#!/bin/bash

# Build deb or rpm packages for honeycomb-tcpagent.
set -e

function usage() {
    echo "Usage: build-pkg.sh -v <version> -t <package_type>"
    exit 2
}

while getopts "v:t:" opt; do
    case "$opt" in
    v)
        version=$OPTARG
        ;;
    t)
        pkg_type=$OPTARG
        ;;
    esac
done

if [ -z "$version" ] || [ -z "$pkg_type" ]; then
    usage
fi

fpm -s dir -n honeycomb-tcpagent \
    -m "Honeycomb <team@honeycomb.io>" \
    -p $GOPATH/bin \
    -v $version \
    -t $pkg_type \
    --post-install=./postinst.sh \
    $GOPATH/bin/honeycomb-tcpagent=/usr/bin/honeycomb-tcpagent \
    ./honeycomb-tcpagent.upstart=/etc/init/honeycomb-tcpagent.conf \
    ./honeycomb-tcpagent.service=/lib/systemd/system/honeycomb-tcpagent.service \
    ./honeycomb-tcpagent.conf=/etc/honeycomb-tcpagent/honeycomb-tcpagent.conf \
