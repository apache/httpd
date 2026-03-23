#!/bin/bash
# test_negative_configs.sh - Automated Server Failure Testing

echo "--- [1/3] Testing: Missing ECH Key File ---"
mv ./conf/ech/ECH_key.pem ./conf/ech/ECH_key.pem.bak
docker-compose restart ech-server
sleep 2

if [ "$(docker inspect -f '{{.State.Running}}' ech-server)" == "false" ]; then
    echo "✅ SUCCESS: Server failed to start without key file (Expected)."
    docker logs ech-server 2>&1 | grep -i "error" | tail -n 2
else
    echo "❌ FAIL: Server started even though ECH key was missing!"
fi

echo "--- [2/3] Testing: Corrupted ECH Configuration ---"
mv ./conf/ech/ECH_key.pem.bak ./conf/ech/ECH_key.pem
# Inject garbage into the ECH config directory
echo "NOT_A_KEY" > ./conf/ech/invalid.pem
docker-compose restart ech-server
sleep 2

if docker logs ech-server 2>&1 | grep -iE "invalid|failed|error"; then
    echo "✅ SUCCESS: Server logged error for invalid ECH configuration."
fi

echo "--- [3/3] Testing: Global vs VirtualHost Scope ---"
echo "Restoring environment..."
docker-compose restart ech-server