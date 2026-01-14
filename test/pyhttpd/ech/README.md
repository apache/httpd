### Step 1: Local DNS Configuration
Map the test domain to your local loopback interface:
```bash
echo "127.0.0.1 ech-test.fyp.local" | sudo tee -a /etc/hosts

### Step 2: Environment Initialization
Set the path to your ECH-enabled OpenSSL build and run the setup script:
export OPENSSL_ECH_PATH=/path/to/your/openssl
./setup_test_env.sh

### Step 3: Start the Server
docker-compose up -d --build

### Step 4: execute test
pytest -s test_ech.py


Test will succeed if firefox parses the provided ECHConfig, Apache uses the SSLECHKeyDir to decrypt ClientHello, and then routes the decrypted request
 to the ech-test.fyp.local VirtualHost, avoiding falling back to the public default.
