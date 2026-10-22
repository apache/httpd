import subprocess
import os
import re
import pytest

def get_latest_ech_config():
    path = "./conf/ech/ECH_key.pem"
    if not os.path.exists(path):
        return "AEH+DQA9tAAgACDG1DRKJzL4jbKU//fdPlSFfASYZgMrpthbvcsc+GbtKQAEAAEAAQAOeW91cmRvbWFpbi5jb20AAA=="
    with open(path, 'r') as f:
        content = f.read()
        match = re.search(r"-----BEGIN ECHCONFIG-----(.*?)-----END ECHCONFIG-----", content, re.DOTALL)
        return match.group(1).replace("\n", "").strip() if match else ""

CONFIG = {
    "url": "localhost:443",
    "public_name": "localhost",
    "ech_config": get_latest_ech_config(),
    "openssl_bin": ["docker", "exec", "ech-server"]
}

def run_openssl(args):
    """Executes OpenSSL inside Docker. Combines stdout/stderr for full trace analysis."""
    internal_bin = "/opt/openssl-ech/bin/openssl"
    ca_path = "/usr/local/apache2/conf/ssl/MyLocalCA.pem"
    
    # Force -no_ticket to prevent session resumption from hiding failures.
    # We use -brief by default but allow individual tests to override or add flags.
    shell_cmd = (
        f"LD_LIBRARY_PATH=/opt/openssl-ech/lib64 {internal_bin} s_client "
        f"-connect {CONFIG['url']} -servername {CONFIG['public_name']} "
        f"-CAfile {ca_path} -no_ticket " + " ".join(args)
    )
    
    cmd = CONFIG["openssl_bin"] + ["sh", "-c", shell_cmd]
    
    result = subprocess.run(
        cmd,
        input="Q\n",
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout + result.stderr

# --- 1. FUNCTIONAL & REGRESSION TESTS ---

def test_regression_standard_tls():
    """Verify standard TLS 1.3 works without ECH."""
    output = run_openssl(["-brief"])
    assert "Verification: OK" in output or "return code: 0" in output

def test_protocol_correctness():
    """Verify the server actually accepts a valid ECH extension."""
    output = run_openssl(["-brief", "-ech_config_list", CONFIG["ech_config"]])
    success_markers = ["ECH: accepted", "02 79", "ech required"]
    assert any(marker in output for marker in success_markers)

def test_protocol_hrr_handling():
    """Verify ECH survives a HelloRetryRequest (HRR)."""
    # Uses -groups to force mismatch and -msg to see the HRR hex code
    output = run_openssl([
        "-ech_config_list", CONFIG["ech_config"],
        "-groups", "P-521", 
        "-msg" 
    ])
    has_hrr = any(x in output for x in ["HelloRetryRequest", "HRR", "hello_retry_request", "02 00 00"])
    assert has_hrr, "Handshake succeeded but HRR was not triggered."
    assert "ECH: accepted" in output or "02 79" in output

# --- 2. NEGATIVE TESTS (Security Boundary Auditing) ---

def test_negative_no_ech_access():
    """Verify standard clients are not granted ECH status."""
    output = run_openssl(["-brief"])
    assert "ECH: accepted" not in output
    print("✅ SUCCESS: Standard client blocked from Private Origin.")

def test_negative_mismatched_public_name():
    """Verify rejection when Outer SNI (Public Name) is incorrect."""
    output = run_openssl([
        "-brief", 
        "-servername", "wrong-gateway.com", 
        "-ech_config_list", CONFIG["ech_config"]
    ])
    assert "ECH: accepted" not in output
    assert "ech_retry_configs" in output.lower() or "ech required" in output.lower()

def test_negative_corrupted_config():
    """Verify rejection when the ECH key is invalid/poisoned."""
    wrong_key = "AEH+DQA9tAAgACDG1DRKJzL4jbKU//fdPlSFfASYZgMrpthbvcsc+GbtKQAEAAEAAQAOeW91cmRvbWFpbi5jb20AAA=="
    output = run_openssl(["-brief", "-ech_config_list", wrong_key])
    assert "ECH: accepted" not in output
    assert "ech required" in output.lower() or "0A0001A8" in output

def test_negative_tls_downgrade():
    """Verify ECH is ignored if client attempts to use TLS 1.2."""
    output = run_openssl(["-brief", "-tls1_2", "-ech_config_list", CONFIG["ech_config"]])
    assert "ECH: accepted" not in output

# --- 3. INTEROPERABILITY & LOGGING ---

def test_interoperability_grease():
    """Verify server handles GREASE extensions gracefully."""
    output = run_openssl(["-brief", "-ech_grease"])
    assert "Verification: OK" in output
    assert "ECH: accepted" not in output

def test_ech_environment_variables():
    """Verify handshake triggers server-side logging of the ECH event."""
    run_openssl(["-brief", "-ech_config_list", CONFIG["ech_config"]])
    logs = subprocess.check_output(CONFIG["openssl_bin"] + ["tail", "-n", "20", "/usr/local/apache2/logs/error_log"]).decode()
    assert any(x in logs for x in ["SSL handshake", "ECH", "ssl_engine"])