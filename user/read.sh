#!/bin/bash

echo
echo "Reading, press 'q' to stop."
echo

line=" "
input=" "

while [ ! "${input,,}" == "q" ]; do
    line=$(head -n 1 /dev/mservtime)

    if [ ! -z "$line" -a "$line" != " " ]; then
        echo "$line"
    fi

    read -t 0.25 -n 1 input
done

echo
echo "Stopped reading."
echo
