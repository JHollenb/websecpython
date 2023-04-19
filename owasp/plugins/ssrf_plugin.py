import requests
from plugins.base_plugin import BasePlugin
from urllib.parse import urlparse

class SSRFPlugin(BasePlugin):
    def __init__(self):
        self.name = "Server-Side Request Forgery (SSRF)"
        self.description = "Detects SSRF flaws in web applications where remote resources are fetched without validating the user-supplied URL."

    def check_ssrf(self, target_url):
        issues = []
        
        # Replace this with a list of crafted URLs that can trigger SSRF vulnerabilities in your application.
        crafted_urls = [
            "http://localhost/",
            "http://127.0.0.1/",
            # Add more crafted URLs
        ]

        for url in crafted_urls:
            try:
                response = requests.get(target_url, params={'url': url}, timeout=5)
                if response.status_code == 200:
                    parsed_url = urlparse(url)
                    issues.append(f"Potential SSRF vulnerability detected with the URL: {parsed_url.scheme}://{parsed_url.hostname}/")
            except requests.exceptions.RequestException:
                pass

        return issues

    def run(self, target_url):
        issues = []
        issues.extend(self.check_ssrf(target_url))
        return {'vulnerable': bool(issues), 'issues': issues}
