#!/bin/bash

ROBOT_DIR=/home/hrst/rn1-host
SERVER_DIR=/home/hrst/rn1-server

echo "hello from map_sync.sh!"
for f in `rsync -zit hrst@${1}:${ROBOT_DIR}/*.map ${SERVER_DIR} | cut -d' ' -f2`
do
	echo "converting ${f}"
	${SERVER_DIR}/map2png ${SERVER_DIR}/$f ${SERVER_DIR}/${f}.png
done
