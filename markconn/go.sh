#!/bin/sh
gcc -o markconn markconn.c -I /usr/include/libnl3/ -lnl-nf-3 -lnl-3
