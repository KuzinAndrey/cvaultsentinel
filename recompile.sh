#!/bin/bash

# CVaultCentinel project
# Re-Build script
# Author: kuzinandrey@yandex.ru

error() { echo; echo "ERROR: $@"; exit 1; }

PROJ="cvaultsentinel"
[ -x ./$PROJ ] && rm ./$PROJ
[ ! -r ./$PROJ.c ] && error "File $PROJ.c not found"

[ ! -r /usr/include/event.h ] && error "For compile you need install [ sudo yum install -y libevent-devel ] library"
[ ! -r /usr/include/openssl/md5.h ] && error "For compile you need install [ sudo yum install -y openssl-devel ] library"

# Options parse
PROD=""
SHAMIR=""

# MAIN PROJECT
PROD="-DPRODUCTION_MODE=1"
SHAMIR="-DSHAMIR_MODE=1"

gcc -Wall -pedantic -pthread $PROD $SHAMIR $PROJ.c \
	-levent -levent_pthreads -lcrypto -o $PROJ || error "Compilation failed"
if [ $? == 0 -a -x ./$PROJ ]; then
	echo "SUCCESSFULLY COMPILED ./$PROJ"
fi
