#/bin/bash

if [ $# -lt 3 ] ; then
  echo "Insufficient number of arguments"
  echo "You should insert the port number for the server application"
  echo "Usage: ./client.sh <domain> <port> <content name>"
  exit 1
fi

if [ $# -gt 3 ] ; then
  echo "Excessive number of arguments"
  echo "You should insert the port number for the server application"
  echo "Usage: ./client.sh <domain> <port> <content name>"
  exit 1
fi

CLIENT=client

if ! [ -f "$CLIENT" ] ; then
  make
fi
  
export LD_LIBRARY_PATH=${HOME}/cve-2019-11477-poc/lib
./client $1 $2 $3
