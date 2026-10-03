import subprocess
import os
import re
import time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

class EchTestEnv:
    def __init__(self):
        self.connection_target = "localhost:443" 
        
        self.public_name = "localhost"
        
        self.private_host = "ech-test.fyp.local"

        self.url = f"https://{self.private_host}"

        self.docker_bin = ["docker", "exec", "ech-server"]
        self.openssl_bin = "/opt/openssl-ech/bin/openssl"
        self.ca_path = "/usr/local/apache2/conf/ssl/MyLocalCA.pem"

    def get_ech_config(self):
        path = "infrastructure/conf/ech/ECH_key.pem"
        if not os.path.exists(path):
            return "AEH+DQA9tAAgACDG1DRKJzL4jbKU//fdPlSFfASYZgMrpthbvcsc+GbtKQAEAAEAAQAOeW91cmRvbWFpbi5jb20AAA=="
        with open(path, 'r') as f:
            content = f.read()
            match = re.search(r"-----BEGIN ECHCONFIG-----(.*?)-----END ECHCONFIG-----", content, re.DOTALL)
            return match.group(1).replace("\n", "").strip() if match else ""

    def run_openssl(self, args):
        shell_cmd = (
            f"LD_LIBRARY_PATH=/opt/openssl-ech/lib64 {self.openssl_bin} s_client "
            f"-connect {self.connection_target} -servername {self.public_name} "
            f"-CAfile {self.ca_path} -no_ticket " + " ".join(args)
        )
        cmd = self.docker_bin + ["sh", "-c", shell_cmd]
        result = subprocess.run(cmd, input="Q\n", capture_output=True, text=True, timeout=10)
        return result.stdout + result.stderr
    
    def run_browser(self, ech_config, use_grease=False):
        """Apache-style Selenium wrapper."""
        options = Options()
        options.add_argument("-headless")
        options.set_preference("network.proxy.type", 0)
        options.set_preference("network.trr.mode", 0)
        
        # ECH enablement
        options.set_preference("network.dns.echconfig.enabled", True)
        options.set_preference("network.dns.local_echconfig", ech_config)
        
        # Trust and local environment settings
        options.set_preference("security.enterprise_roots.enabled", True)
        options.set_preference("network.http.ocsp.enabled", False)
        
        if use_grease:
            options.set_preference("network.tls.grease.enabled", True)

        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(20)
        
        try:
            driver.get(self.url)
            time.sleep(2)
            return driver.page_source
        finally:
            driver.quit()