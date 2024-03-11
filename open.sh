#!/bin/bash

url="http://127.0.0.1:6969"

. ./.shamir_creds.txt

#echo $key1
curl -s "$url/shamir?key=$key1"

#echo $key2
curl -s "$url/shamir?key=$key2"

#echo $key3
curl -s "$url/shamir?key=$key3"
