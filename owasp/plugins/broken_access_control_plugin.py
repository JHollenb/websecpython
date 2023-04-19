# Example Plugin (plugins/broken_access_control_plugin.py)
# https://owasp.org/Top10/A01_2021-Broken_Access_Control/

import requests
from bs4 import BeautifulSoup
from .base_plugin import BasePlugin

class BrokenAccessControlPlugin(BasePlugin):
    def __init__(self):
        self.plugin_name = "A01 - Broken Access Control Plugin" 
        super().__init__(self.plugin_name)

    def run(self, target_url):
        response = requests.get(target_url)
        soup = BeautifulSoup(response.content, "html.parser")

        directory_listing_enabled = self.is_directory_listing_enabled(soup)
        sensitive_files_exposed = self.check_sensitive_files(target_url)

        return {
            "plugin_name": self.plugin_name,
            "directory_listing_enabled": directory_listing_enabled,
            "sensitive_files_exposed": sensitive_files_exposed,
            "vulnerable": directory_listing_enabled or bool(sensitive_files_exposed)
        }

    def is_directory_listing_enabled(self, soup):
        # Check if directory listing is enabled by looking for specific tags and attributes
        if soup.find("a", href=True, text="Parent Directory"):
            return True
        if soup.find_all("h1") and "Index of" in soup.h1.text:
            return True
        return False

    def check_sensitive_files(self, target_url):
        sensitive_files = [".git", ".bak", ".swp", ".env"]
        exposed_files = []

        for file in sensitive_files:
            response = requests.get(f"{target_url}/{file}")
            if response.status_code == 200:
                exposed_files.append(file)

        return exposed_files

