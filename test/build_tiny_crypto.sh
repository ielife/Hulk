#!/bin/sh

gcc tiny_crypto.c -o tiny_crypto -I ../include -L ../library -lmbedtls -lmbedx509 -lmbedcrypto
