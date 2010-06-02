#! /bin/bash
#
# Add to git new files created by bfdd patch
#
# Run from quagga's top dir as:
# . bfdd/quagga-git-add.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

chmod a+rx bfdd/*.sh
git add bfdd
#git add doc/bfd*
git add lib/bfd.c
git add lib/bfd.h
git add pkgsrc/bfdd.sh.in
git add zebra/zserv_bfd.c
git add zebra/zserv_bfd.h
