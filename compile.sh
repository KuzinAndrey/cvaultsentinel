#!/bin/bash

PROJ="cvaultsentinel"
[ -x ./$PROJ ] && rm ./$PROJ
[ ! -r ./$PROJ.c ] && "File $PROJ.c not found" && exit 1

[ ! -r /usr/include/event.h ] && echo "For compile you need install [ sudo yum install -y libevent-devel ] library" && exit 1
[ ! -r /usr/include/openssl/md5.h ] && echo "For compile you need install [ sudo yum install -y openssl-devel ] library" && exit 2

if [ ! -r gen_table.h ]; then
	echo "#ifndef _CVAULTSENTINEL_GEN_TABLE_H_" > gen_table.h
	echo "#define _CVAULTSENTINEL_GEN_TABLE_H_" >> gen_table.h
	echo "unsigned char gen_crypt[] = {" >> gen_table.h
	dd if=/dev/urandom bs=1K count=1 status=none | xxd -i >> gen_table.h
	echo "};" >> gen_table.h
	echo "const unsigned long gen_crypt_size = sizeof(gen_crypt) / sizeof(gen_crypt[0]);" >> gen_table.h
	echo "#endif /*_CVAULTSENTINEL_GEN_TABLE_H_*/" >> gen_table.h
fi

PROD=""
[ ! -z $1 ] && [ "$1" = "prod" ] && PROD="-DPRODUCTION_MODE=1"

gcc -s -Wall -pedantic -pthread $PROD $PROJ.c \
	-levent -levent_pthreads -lcrypto -o $PROJ
