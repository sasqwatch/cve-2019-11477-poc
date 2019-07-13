#/bin/bash

if [ $# -lt 1 ] ; then
  echo "Insufficient number of arguments"
  echo "You should insert the port number for the server application"
  echo "Usage: ./server.sh <port>"
  exit 1
fi

if [ $# -gt 1 ] ; then
  echo "Excessive number of arguments"
  echo "You should insert the port number for the server application"
  echo "Usage: ./server.sh <port>"
  exit 1
fi

SERVER=server

if ! [ -f "$SERVER" ] ; then
  make
fi
  
export LD_LIBRARY_PATH=${HOME}/cve-2019-11477-poc/lib
./server $1
