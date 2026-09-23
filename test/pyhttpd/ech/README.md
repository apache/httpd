# ECH Apache Implementation & Verification Suite

This repository contains the source code, build instructions, and an automated testing suite for Encrypted Client Hello (ECH) within the Apache `httpd` (mod_ssl) directory.

---

## 1. Build & Compilation Guide
To reproduce the experimental environment, you must build both the OpenSSL fork and Apache from source to ensure the ECH state machine is correctly linked.

### A. Build ECH-Enabled OpenSSL
We utilize a specific fork of OpenSSL that includes HPKE and ECH protocol support.

# Clone and enter the experimental repository
git clone (https://github.com/sftcd/openssl.git) openssl-ech
cd openssl-ech

# Configure for a local prefix to avoid system conflicts
./config --prefix=$HOME/openssl-ech --openssldir=$HOME/openssl-ech -Wl,-rpath,'$(LIBRPATH)'

# Compile and install
make -j$(nproc)
make install


B. Build ECH-Enabled Apache (httpd)
Apache must be linked against the custom OpenSSL build created above.
git clone (https://github.com/apache/httpd.git) httpd-ech
cd httpd-ech

# Configure with custom SSL path and static dependency hooks
./buildconf
./configure --prefix=$HOME/apache-ech \
            --enable-ssl \
            --enable-so \
            --with-ssl=$HOME/openssl-ech \
            --enable-mods-shared=all \
            --enable-ssl-staticlib-deps

make -j$(nproc)
make install

2. Verification Suite Setup
A. Shell Environment
Set these variables in your active terminal to point the verification tools to your custom binaries.

export OPENSSL_ECH_PATH=$HOME/openssl-ech
export OPENSSL_CONF=/etc/ssl/openssl.cnf
export PATH=$OPENSSL_ECH_PATH/bin:$PATH
export LD_LIBRARY_PATH=$OPENSSL_ECH_PATH/lib64:$LD_LIBRARY_PATH

B. Network Configuration
echo "127.0.0.1 ech-test.fyp.local" | sudo tee -a /etc/hosts

C. Python Dependencies
pip install -r requirements.txt

D. Cryptographic Initialization
Generate the PKI hierarchy (Root CA, Server Certs) and the ECH key material.
cd scripts/
./setup_test_env.sh
cd ..

 3. Infrastructure Orchestration
Deploy the containerized server. We use a volume-wipe strategy to ensure configuration idempotency.
cd infrastructure/
docker-compose down -v
docker-compose up -d --build

# Initialize a clean configuration backup for robustness testing
docker exec ech-server cp /usr/local/apache2/conf/httpd.conf /usr/local/apache2/conf/httpd.conf.bak
cd ..

Running the Full Suite
pytest -v cases/

Security Audit (Wire-Level)
To verify that no SNI information leaks in cleartext, run the Tshark-based auditor:
sudo ./scripts/verify_ech.sh

Project Structure
/cases: Modular pytest logic.

/infrastructure: Dockerfiles and Apache httpd.conf templates.

/lib: Environment abstractions and Selenium/WebDriver drivers.

/scripts: Setup and wire-level verification tools.

/conf: Storage for generated .pem keys and ECHConfigs.

Success Criteria
Verification is successful if:

test_01 and test_02 return PASSED (Protocol and Browser Success).

test_04 identifies a Syntax Error (Robustness Success).

verify_ech.sh detects zero occurrences of the string ech-test.fyp.local in the cleartext portion of the TLS ClientHello.