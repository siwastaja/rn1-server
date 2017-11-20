#!/bin/sh
gcc -std=c99 -Wall -shared -o libprotocol_rn1.so -fPIC rn1server.c -lwebsockets -luv
sudo cp libprotocol_rn1.so /usr/local/share/libwebsockets-test-server/plugins/
sudo cp html/rn1.html /usr/local/share/libwebsockets-test-server
