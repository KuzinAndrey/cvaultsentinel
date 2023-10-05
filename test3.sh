#!/bin/bash

F=$(mktemp -p /dev/shm)
F1=$(mktemp -p /dev/shm)
F2=$(mktemp -p /dev/shm)

COUNT=5000000

while [ $COUNT -gt 0 ]; do
	S=$RANDOM
	dd if=/dev/urandom bs=1 count=$S status=none > $F
	[ $? != 0 ] && echo CURL_ERROR && break

	curl -s --data-binary @${F} -X POST http://localhost:6969/encrypt > $F1
	[ $? != 0 ] && echo CURL_ERROR && break

	curl -s --data-binary @${F1} -X POST http://localhost:6969/decrypt > $F2
	[ $? != 0 ] && echo CURL_ERROR && break

	if ! cmp $F $F2 ; then
		echo -n '!'
	else
		echo -n '.'
	fi
	COUNT=$(($COUNT - 1))
done

rm $F $F1 $F2
