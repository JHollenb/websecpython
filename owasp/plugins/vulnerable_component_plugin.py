import os
import json
import subprocess
from .base_plugin import BasePlugin
from requests.exceptions import RequestException
import requests

class VulnerableOutdatedComponentsPlugin(BasePlugin):
    plugin_name = "A06:2021 - Vulnerable and Outdated Components"

    def __init__(self):
        super().__init__(self.plugin_name)

    def check_version_headers(self, target_url):
        outdated_components = []

        try:
            response = requests.get(target_url)

            server_header = response.headers.get('Server', '')
            powered_by_header = response.headers.get('X-Powered-By', '')

            if server_header:
                outdated_components.append(f"Server: {server_header}")
            if powered_by_header:
                outdated_components.append(f"X-Powered-By: {powered_by_header}")

        except RequestException:
            pass

        return outdated_components

    def check_js_libraries(self, target_url):
        result = subprocess.run(['retire', '--jspath', target_url, '--outputformat', 'json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode == 0:
            retire_output = json.loads(result.stdout)
            return retire_output
        return []


    def run(self, target_url):
        outdated_server_components = self.check_version_headers(target_url)
        outdated_js_libraries = self.check_js_libraries(target_url)

        vulnerable = bool(outdated_server_components) or bool(outdated_js_libraries)
        details = []

        if vulnerable:
            if outdated_server_components:
                details.append("The following server components are outdated or vulnerable:")
                details.extend(outdated_server_components)
            
            if outdated_js_libraries:
                details.append("The following JavaScript libraries are outdated or vulnerable:")

                for finding in outdated_js_libraries:
                    if isinstance(finding, dict):
                        library = finding.get('library', '')
                        version = finding.get('version', '')
                        details.append(f"{library} {version}")
                    else:
                        print(f"Unexpected finding format: {finding}")


        return {
            "vulnerable": vulnerable,
            "plugin_name": self.plugin_name,
            "details": " ".join(details)
        }

