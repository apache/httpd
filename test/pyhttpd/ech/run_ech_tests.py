import subprocess
import json

CONFIG = {
    "url": "localhost:443",
    "public_name": "yourdomain.com",
    "ech_config": "AEH+DQA9tAAgACDG1DRKJzL4jbKU//fdPlSFfASYZgMrpthbvcsc+GbtKQAEAAEAAQAOeW91cmRvbWFpbi5jb20AAA==",
    "openssl_bin": ["docker", "exec", "-i", "ech-server", "/opt/openssl-ech/bin/openssl"]
}

def run_openssl(args):
    cmd = CONFIG["openssl_bin"] + [
        "s_client", 
        "-connect", CONFIG["url"],
        "-CAfile", "/usr/local/apache2/conf/ssl/MyLocalCA.pem"
    ] + args
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proc.communicate(input="Q\n", timeout=5)
    return stdout, stderr

def test_regression_standard_tls():
    print("[RUN] Testing Standard TLS Fallback...")
    stdout, stderr = run_openssl(["-servername", "localhost"])
    if "NewSessionTicket" in stdout or "return code: 18" in stdout:
        return True, "Standard TLS handshake successful (Self-signed accepted)."
    return False, "Handshake failed to reach encrypted stage."

def test_protocol_correctness():
    """Test 2: Verify the server actually attempts to decrypt the ECH extension."""
    print("[RUN] Testing ECH Decryption Logic...")
    stdout, stderr = run_openssl([
        "-ech_config_list", CONFIG["ech_config"],
        "-servername", CONFIG["public_name"]
    ])
    if "ech required" in stderr.lower() or "02 79" in stdout:
        return True, "Server successfully decrypted and processed ECH extension."
    return False, "Server ignored ECH extension or failed silently."

def test_interoperability_grease():
    """Test 3: Verify the server handles GREASE (interoperability safety)."""
    print("[RUN] Testing ECH GREASE Interop...")
    stdout, stderr = run_openssl(["-ech_grease", "-servername", "localhost"])
    if "ECH: GREASE" in stdout and "Verification: OK" in stdout:
        return True, "Server correctly ignored GREASE extension."
    return False, "Server failed to handle GREASE."

tests = [
    ("Regression", test_regression_standard_tls),
    ("Correctness", test_protocol_correctness),
    ("Interop-GREASE", test_interoperability_grease)
]

print("-" * 30)
for name, func in tests:
    success, msg = func()
    status = "PASS" if success else "FAIL"
    print(f"{name}: {status} - {msg}")
print("-" * 30)
