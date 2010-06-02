#! /bin/bash
#
# Configure for minimum Quagga build needed for bfdd.
#
# Run from quagga's top dir as:
# . bfdd/quagga-configure.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

./configure --disable-ripd --disable-ripngd --disable-ospfd --disable-ospf6d --disable-watchquagga --disable-ospfapi --disable-ospfclient --disable-rtadv --disable-irdp --enable-tcp-zebra --enable-ipv6
