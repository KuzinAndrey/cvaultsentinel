#!/bin/sh

#DATA='dGVzdCBzdHJpbmcgdG8gZGVjb2RlMTIzCg=='
DATA='Q1+CL764j2jJ4+0c+vfIWOz3LIf3jS8M8bJA+dT38ba0P+S+plQbsw=='

curl -d "$DATA" -H "Content-Type: application/json" -X POST http://localhost:6969/decrypt
