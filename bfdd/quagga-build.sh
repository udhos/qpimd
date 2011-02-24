#! /bin/bash
#
# Build minimum Quagga needed for bfdd.
#
# Run from quagga's top dir as:
# ./bfdd/quagga-build.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

./bfdd/quagga-memtypes.sh && ./bfdd/quagga-bootstrap.sh && ./bfdd/quagga-configure.sh && make
