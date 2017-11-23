#!/bin/bash

ROBOT_DIR=/home/hrst/rn1-host
SERVER_DIR=/home/hrst/rn1-server
RETVAL=0

echo "hello from map_sync.sh!"
if [[ "$2" == "del" ]]
then
	echo "Deleting maps first"
	rm -f ${SERVER_DIR}/*.map ${SERVER_DIR}/*.png
fi

> ${SERVER_DIR}/synced_maps.txt
for f in `rsync -zit hrst@${1}:${ROBOT_DIR}/*.map ${SERVER_DIR} | cut -d' ' -f2`
do
	echo "converting ${f}"
	echo ${f} >> ${SERVER_DIR}/synced_maps.txt
	${SERVER_DIR}/map2png ${SERVER_DIR}/$f ${SERVER_DIR}/${f}.png
	RETVAL=123
done
exit $RETVAL
