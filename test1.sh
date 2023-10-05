#!/bin/sh

DATA='{"key1":"value1", "key2":"value2"}'
DATA='{"key1":"value1"}'
echo -n $DATA | xxd

F=$(mktemp -p /dev/shm)
#dd if=/dev/urandom bs=1K count=1 status=none > $F
#dd if=/dev/urandom bs=1K count=1 status=none > $F
dd if=/dev/urandom bs=1 count=111 status=none > $F
echo $F
curl -d "$DATA" -H "Content-Type: application/json" -X POST http://localhost:6969/encrypt

#curl --verbose --data-binary @${F} -H "Content-Type: application/octet-stream" -X POST http://localhost:6969/encrypt
rm $F