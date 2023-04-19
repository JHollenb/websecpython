import requests
from bs4 import BeautifulSoup
from .base_plugin import BasePlugin
from requests.exceptions import RequestException

class SecurityMisconfigurationPlugin(BasePlugin):
    plugin_name = "A05:2021 - Security Misconfiguration"

    def __init__(self):
        super().__init__(self.plugin_name)
        self.timeout = 5
        self.DEBUG = False

    def check_error_handling(self, target_url):
        try:
            response = requests.get(target_url, verify=False, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            if soup.find(text=lambda text: 'Exception' in text or 'Error' in text):
                return True
        except RequestException:
            pass
        except requests.exceptions.ConnectTimeout:
            print(f"Error in find_weak_encryption: Connection to {url} timed out.")

        return False

    def check_security_headers(self, target_url):
        try:
            response = requests.get(target_url, verify=False, timeout=self.timeout)

            headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
            ]

            for header in headers:
                if header not in response.headers:
                    return False

        except RequestException:
            return False
        except requests.exceptions.ConnectTimeout:
            if self.DEBUG:
                print(f"Error in find_weak_encryption: Connection to {url} timed out.")
            return False

        return True

    def check_directory_listing(self, target_url):
        try:
            response = requests.get(target_url, verify=False, timeout=self.timeout)

            if "<title>Index of /" in response.text:
                return True
        except RequestException:
            pass
        except requests.exceptions.ConnectTimeout:
            print(f"Error in find_weak_encryption: Connection to {url} timed out.")

        return False

    def check_software_version(self, target_url):
        # This function is a placeholder, as determining software version requires more specific checks and analysis
        return False

    def run(self, target_url):
        error_handling_vulnerable = self.check_error_handling(target_url)
        security_headers_vulnerable = not self.check_security_headers(target_url)
        directory_listing_vulnerable = self.check_directory_listing(target_url)
        software_version_vulnerable = self.check_software_version(target_url)

        vulnerable = error_handling_vulnerable or security_headers_vulnerable or directory_listing_vulnerable or software_version_vulnerable
        details = []

        if error_handling_vulnerable:
            details.append("The application's error handling reveals sensitive information.")
        if security_headers_vulnerable:
            details.append("The server does not send security headers or they are not set to secure values.")
        if directory_listing_vulnerable:
            details.append("Directory listing is enabled on the server, exposing potential sensitive files.")
        if software_version_vulnerable:
            details.append("The software is out of date or vulnerable.")

        return {
            "vulnerable": vulnerable,
            "plugin_name": self.plugin_name,
            "details": " ".join(details)
        }

