#!/bin/sh
echo Content-type: text/plain
echo
if [ -z "$PATH_INFO" ]; then
    echo "_(none)_"
else
    echo _${PATH_INFO}_
fi
