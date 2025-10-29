#!/bin/bash

IFNAME="wlp1s0"

if [ ! -z "$1" -a "$1" != " " ]; then
    IFNAME="$1"
fi

echo "Starting with interface name: ${IFNAME}."
echo -n "$IFNAME" > /dev/mservtime
echo "Started with interface name: ${IFNAME}."

