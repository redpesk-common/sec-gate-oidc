#!/bin/sh
echo "Start some dummy API for test"

CONFDIR=`dirname $0`
CONFNAME="oidc"

# default spawn-binding installation
if test -z "$AFB_SPAWN_INSTALL"
then
    AFB_SPAWN_INSTALL="/usr/redpesk/spawn-binding"
fi    

if test -z "$AFB_SPAWN_PORT"
then 
    AFB_SPAWN_PORT=1056
fi

# make sure we have spawn binding avaliable
if ! test -f $AFB_SPAWN_INSTALL/lib/spawn-binding.so
then
    echo spawn-binding not install into $AFB_SPAWN_INSTALL
fi

APIS_SVC=""
for FILE in $CONFDIR/$CONFNAME-api-test*.json
do
    BASENAME=`basename $FILE .json | awk -F '-' '{print $3}'`
    APIS_SVC="$APIS_SVC --ws-server=unix:@$BASENAME"
done
export AFB_SPAWN_CONFIG=$CONFDIR
echo "Check APIs with http://localhost:$AFB_SPAWN_PORT/devtools/index.html"
set -x
afb-binder --name=spawn-binding --name=afb-$CONFNAME-test --roothttp=$CONFDIR --binding=$AFB_SPAWN_INSTALL/lib/spawn-binding.so --ws-server=tcp:localhost:1235/test3 --port=$AFB_SPAWN_PORT $APIS_SVC
