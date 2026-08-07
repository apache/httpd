#!/bin/sh

CT=$(echo ${QUERY_STRING}|awk -F: '{print $1'})
LOC=$(echo ${QUERY_STRING}|awk  -F: '{print $2'})

echo Content-type: ${CT}
echo Location: ${LOC}
echo
echo "this is action.sh"
