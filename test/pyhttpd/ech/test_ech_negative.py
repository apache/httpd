import os
import pytest
import tempfile
import shutil
import time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

class TestEchNegative:

    def run_negative_browser_test(self, ech_config=None, use_ech=False):
        options = Options()
        options.add_argument("-headless")
        
        # Isolated Profile
        self.temp_dir = tempfile.mkdtemp()
        options.add_argument("-profile")
        options.add_argument(self.temp_dir)
        
        # Kill Client-Side Resumption
        options.set_preference("network.session-resumption.enabled", False)
        options.set_preference("security.tls.enable_0rtt_data", False)
        
        # DNS/Network Stability
        options.set_preference("network.trr.mode", 0) 
        options.set_preference("network.proxy.type", 0)
        options.set_preference("network.dns.localDomains", "ech-test.fyp.local")

        # Set ECH Prefs safely
        options.set_preference("network.dns.echconfig.enabled", use_ech)
        if use_ech and ech_config:
            options.set_preference("network.dns.local_echconfig", ech_config)
        
        driver = webdriver.Firefox(options=options)
        try:
            # Timestamp busts any remaining caches
            driver.get(f"https://ech-test.fyp.local/?t={time.time()}")
            return driver.page_source
        finally:
            driver.quit()
            shutil.rmtree(self.temp_dir)

    def test_ech_disabled_fallback(self):
        print("\n[AUDIT] Testing Handshake without ECH Extension...")
        page_source = self.run_negative_browser_test(use_ech=False)
        
        assert "Public Gateway" in page_source
        assert "ECH Decrypted Successfully" not in page_source
        print("✅ PASSED: Identity Hidden. Server defaulted to Public Gateway.")

    def test_ech_invalid_key_fallback(self):
        print("\n[AUDIT] Testing Handshake with Poisoned ECH Key...")
        poisoned_key = "AEH+DQA9tAAgACDG1DRKJzL4jbKU//fdPlSFfASYZgMrpthbvcsc+GbtKQAEAAEAAQAOeW91cmRvbWFpbi5jb20AAA=="
        page_source = self.run_negative_browser_test(ech_config=poisoned_key, use_ech=True)
        
        assert "Public Gateway" in page_source
        assert "ECH Decrypted Successfully" not in page_source
        print("✅ PASSED: Decryption failed. Server protected the Inner Name.")
