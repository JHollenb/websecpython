# plugins/cryptographic_failures_plugin.py
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from .base_plugin import BasePlugin

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CryptographicFailuresPlugin(BasePlugin):
    def __init__(self):
        self.plugin_name = "A02:2022 - Cryptographic Failures"
    
    def run(self, url):
        try:
            weak_encryption_result = self.find_weak_encryption(url)
            if weak_encryption_result:
                return {
                    "vulnerable": True,
                    "details": weak_encryption_result,
                    "plugin_name": self.plugin_name,
                }
        except Exception as e:
            print(f"Error in {self.plugin_name}: {e}")

        return None

    def find_weak_encryption(self, url):
        response = self.send_https_request(url)
        if not response:
            return None

        cipher_suite = self.extract_cipher_suite(response)
        if self.is_weak_cipher(cipher_suite):
            return f"Weak encryption detected: {cipher_suite}"
        
        return None

    def send_https_request(self, url):
        try:
            https_url = url.replace("http://", "https://")
            response = requests.get(https_url, verify=False, timeout=10)
            return response
        except Exception as e:
            print(f"Error in find_weak_encryption: {e}")
            return None

    def extract_cipher_suite(self, response):
        if hasattr(response, 'raw') and hasattr(response.raw, '_connection'):
            cipher_suite = response.raw._connection.sock.cipher()
            return cipher_suite[0] if cipher_suite else None
        return None

    def is_weak_cipher(self, cipher):
        weak_ciphers = ["DES", "3DES", "RC4", "MD5", "SHA1"]
        return any(weak_cipher in cipher for weak_cipher in weak_ciphers)

