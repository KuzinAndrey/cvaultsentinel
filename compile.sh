#!/bin/bash

# CVaultCentinel project
# Build script
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
while [ ! -z "$1" ]; do
	case "$1" in
	"prod") PROD="-DPRODUCTION_MODE=1" ;;
	"sham") SHAMIR="-DSHAMIR_MODE=1" ;;
	esac
	shift
done

# GENERATE PASSWORD SPACE
if [ ! -r gen_table.h ]; then
	echo "#ifndef _CVAULTSENTINEL_GEN_TABLE_H_" > gen_table.h
	echo "#define _CVAULTSENTINEL_GEN_TABLE_H_" >> gen_table.h

	echo "const char *build_id = \"$(cat /proc/sys/kernel/random/uuid | tr -d "\n")\";" >> gen_table.h

	echo "unsigned char gen_crypt[] = {" >> gen_table.h
	dd if=/dev/urandom bs=1M count=1 status=none | xxd -i >> gen_table.h
	echo "};" >> gen_table.h
	echo "const unsigned long gen_crypt_size = sizeof(gen_crypt) / sizeof(gen_crypt[0]);" >> gen_table.h
	echo "#endif /*_CVAULTSENTINEL_GEN_TABLE_H_*/" >> gen_table.h
fi

# SHAMIR MODE
if [ -r gen_table.h -a ! -z "$SHAMIR" ]; then
	[ -x ./shamir_test ] && rm ./shamir_test
	gcc -Wall -pedantic shamir_test.c -o shamir_test || error "compilation failed"
	./shamir_test && rm ./shamir_test || error "test failed"

	gcc build_in_shamir.c -o build_in_shamir -lcrypto || error "compilation failed"
	./build_in_shamir > .shamir_creds.txt && rm ./build_in_shamir || error "shamir build in failed"
fi

# MAIN PROJECT
gcc -s -Wall -pedantic -pthread $PROD $SHAMIR $PROJ.c \
	-levent -levent_pthreads -lcrypto -o $PROJ || error "Compilation failed"
if [ $? == 0 -a -x ./$PROJ ]; then
	echo "SUCCESSFULLY COMPILED ./$PROJ"
fi
