import os
import time
import pytest
import re
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

class TestEch:

    @pytest.fixture(autouse=True)
    def setup_paths(self):
        """Pre-test setup: Locates keys and extracts the ECHConfig string."""
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.ech_key_path = os.path.join(self.base_dir, "conf", "ech", "ECH_key.pem")

        if os.path.exists(self.ech_key_path):
            with open(self.ech_key_path, 'r') as f:
                content = f.read()
                match = re.search(r"-----BEGIN ECHCONFIG-----(.*?)-----END ECHCONFIG-----", content, re.DOTALL)
                if match:
                    self.ech_config = match.group(1).replace("\n", "").strip()
                else:
                    pytest.fail("Found ECH_key.pem but no 'BEGIN ECHCONFIG' block inside!")
        else:
            pytest.fail(f"ECH Key not found. Run setup_test_env.sh first.")

    def run_browser_test(self, ech_config, use_grease=False):
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
        
        # Set a shorter timeout so you don't wait 3 minutes for a failure
        driver.set_page_load_timeout(20) 
        
        try:
            driver.get("https://ech-test.fyp.local")
            time.sleep(2)
            return driver.page_source
        finally:
            driver.quit()

    def test_ech_handshake_success(self):
        """Test 1: Standard ECH Handshake."""
        print("\n[RUN] Testing Standard ECH Handshake...")
        page_source = self.run_browser_test(self.ech_config)
        # CHANGED: Match the actual output from your terminal error
        assert "ECH Decryption Successful" in page_source 
        print("✅ SUCCESS: ECH Decrypted and inner content served.")

    def test_ech_with_grease(self):
        """Test 2: GREASE Interoperability."""
        print("\n[RUN] Testing ECH with GREASE enabled...")
        page_source = self.run_browser_test(self.ech_config, use_grease=True)
        # CHANGED: Match the actual output
        assert "ECH Decryption Successful" in page_source
        print("✅ SUCCESS: GREASE handled correctly.")