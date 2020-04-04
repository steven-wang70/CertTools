#!/bin/bash

OPENSSL_DIR=~/openssl/openssl-1.0.2e
INCLUDE_DIR=$OPENSSL_DIR/include
LIB_DIR=$OPENSSL_DIR

gcc -I$INCLUDE_DIR readCerts.cpp -L$LIB_DIR -lcrypto -ldl -o readCerts.out

