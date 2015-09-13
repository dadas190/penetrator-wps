#!/bin/sh
gcc penetrator.c -lpcap -lcrypto -lrt -pthread -openetrator
mv penetrator /usr/bin/penetrator
echo "PENETRATOR was successfully installed, run 'penetrator'"

