#!/bin/bash

echo "hello from map_sync.sh!"
for f in `rsync -zit hrst@proto4:/home/hrst/rn1-host/*.map /home/hrst/rn1-server/ | cut -d' ' -f2`
do
	echo "converting ${f}"
	/home/hrst/rn1-server/map2png /home/hrst/rn1-server/$f /home/hrst/rn1-server/${f}.png
done
