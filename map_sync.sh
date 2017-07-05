#!/bin/bash

echo "hello from map_sync.sh!"
for f in `rsync -zi hrst@proto4:/home/hrst/rn1-host/*.map . | grep -v ">f..T......" | cut -d' ' -f2`
do
	echo "converting ${f}"
	./map2png $f ${f}.png
done
