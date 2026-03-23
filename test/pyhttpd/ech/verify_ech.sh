#!/bin/bash

INTERFACE="lo"               
TARGET_SNI="localhost"       
OUTPUT_FILE="ech_capture.pcap"
DURATION=15                  

echo "--- ECH Security Auditor Starting ---"
echo "[INFO] Listening on $INTERFACE for $DURATION seconds..."
echo "[INFO] Searching for cleartext leaks of: $TARGET_SNI"

tshark -i $INTERFACE -a duration:$DURATION \
       -Y "tls.handshake.extensions_server_name == \"$TARGET_SNI\"" \
       -w $OUTPUT_FILE > capture_log.txt 2>&1

MATCH_COUNT=$(tshark -r $OUTPUT_FILE 2>/dev/null | wc -l)

if [ "$MATCH_COUNT" -gt 0 ]; 
    echo " SNI LEAK DETECTED"
    exit 1
else
    echo "  SUCCESS: Handshake Encrypted."
    echo "  No cleartext SNI found on the wire."
    exit 0
fi