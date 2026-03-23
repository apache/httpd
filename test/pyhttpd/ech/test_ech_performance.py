import time
import statistics
import os
import subprocess
import re

# Reuse your existing config and runner
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

def timed_handshake(args):
    """Executes a handshake and returns the duration in milliseconds."""
    internal_bin = "/opt/openssl-ech/bin/openssl"
    ca_path = "/usr/local/apache2/conf/ssl/MyLocalCA.pem"
    
    shell_cmd = (
        f"LD_LIBRARY_PATH=/opt/openssl-ech/lib64 {internal_bin} s_client "
        f"-connect {CONFIG['url']} -servername {CONFIG['public_name']} "
        f"-CAfile {ca_path} -brief -no_ticket " + " ".join(args)
    )
    
    cmd = CONFIG["openssl_bin"] + ["sh", "-c", shell_cmd]
    
    start = time.perf_counter()
    subprocess.run(cmd, input="Q\n", capture_output=True, text=True)
    end = time.perf_counter()
    
    return (end - start) * 1000  # Convert to ms

def run_benchmark(iterations=20):
    print(f"--- Starting ECH Performance Audit ({iterations} iterations) ---")
    
    standard_times = []
    ech_times = []

    # 1. Benchmark Standard TLS 1.3 (Baseline)
    print("Benchmarking Standard TLS 1.3...", end="", flush=True)
    for _ in range(iterations):
        standard_times.append(timed_handshake([]))
    print(" Done.")

    # 2. Benchmark ECH (Decryption Overhead)
    print("Benchmarking ECH Handshake...", end="", flush=True)
    for _ in range(iterations):
        ech_times.append(timed_handshake(["-ech_config_list", CONFIG["ech_config"]]))
    print(" Done.")

    # Calculate Stats
    avg_std = statistics.mean(standard_times)
    avg_ech = statistics.mean(ech_times)
    overhead = avg_ech - avg_std
    percentage = (overhead / avg_std) * 100

    print("\n" + "="*40)
    print(f"{'Metric':<25} | {'Result'}")
    print("-" * 40)
    print(f"{'Avg Standard TLS':<25} | {avg_std:.2f} ms")
    print(f"{'Avg ECH Handshake':<25} | {avg_ech:.2f} ms")
    print(f"{'Decryption Overhead':<25} | {overhead:.2f} ms")
    print(f"{'Latency Increase':<25} | {percentage:.2f} %")
    print("="*40)
    
    if percentage < 15:
        print("RESULT: Performance overhead is within acceptable RFC limits.")
    else:
        print("RESULT: Significant overhead detected. Check CPU scaling.")

if __name__ == "__main__":
    run_benchmark(30)