#!/bin/bash

PACKAGE=$3
TMPFILE="mockgen_tmp.go"
# uppercase the name of the interface
INTERFACE_NAME="$(tr '[:lower:]' '[:upper:]' <<< ${4:0:1})${4:1}"

# create a public alias for the interface, so that mockgen can process it
echo -e "package $1\n" > $TMPFILE
echo "type $INTERFACE_NAME = $4" >> $TMPFILE

mockgen -package $1 -self_package $PACKAGE -destination $2 $PACKAGE $INTERFACE_NAME
mv $2 $TMPFILE && sed 's/qtls.ConnectionState/ConnectionState/g' $TMPFILE > $2
goimports -w $2

rm $TMPFILE
