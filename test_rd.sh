#!/bin/sh

cd /usr/src/distrib/i386/ramdisk_cd
make clean
make
install -F -m 644 obj/bsd.gz /bsd.rd
