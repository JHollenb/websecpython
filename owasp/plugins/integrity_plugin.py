import requests
from bs4 import BeautifulSoup

import hashlib

class IntegrityPlugin:

    def __init__(self):
        self.name = "Integrity Plugin"
        self.description = "This plugin checks for software and data integrity failures."

    def run(self, target_url):
        issues = []
        issues.extend(self.check_unsecured_resources(target_url))
        return {'vulnerable': bool(issues), 'issues': issues}

    def check_unsecured_resources(self, target_url):
        issues = []
        response = requests.get(target_url)
        if response.status_code == 200:
            resources = self.extract_resources(response.text)
            for resource in resources:
                if not self.is_https(resource):
                    issues.append(f"Unsecured resource: {resource}")
        return issues

    def extract_resources(self, html_content):
        resources = []
        soup = BeautifulSoup(html_content, 'html.parser')
        resources.extend([link['href'] for link in soup.find_all('link', href=True)])
        resources.extend([script['src'] for script in soup.find_all('script', src=True)])
        return resources

    def get_url_scheme(self, url):
        return url.split(':')[0]

    def is_https(self, url):
        return self.get_url_scheme(url) == 'https'

# Sample usage:
# plugin = IntegrityPlugin()
# issues = plugin.run('http://example.com')
# for issue in issues:
#     print(issue)

