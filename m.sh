#!/bin/sh
gcc -Wall -shared -o libprotocol_rn1.so -fPIC rn1server.c -lwebsockets -luv
sudo cp libprotocol_rn1.so /usr/local/share/libwebsockets-test-server/plugins/
