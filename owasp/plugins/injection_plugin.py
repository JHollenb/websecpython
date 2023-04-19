import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .base_plugin import BasePlugin

from json import JSONDecodeError
from requests.exceptions import RequestException


class InjectionPlugin(BasePlugin):
    plugin_name = "A03:2021 - Injection"

    def __init__(self):
        super().__init__(self.plugin_name)

    def check_sql_injection(self, target_url):
        vulnerable = False
        payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]

        for payload in payloads:
            try:
                injected_url = f"{target_url}?id={payload}"
                response = requests.get(injected_url)

                if response.status_code == 500:
                    vulnerable = True
                    break

                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.find(text=lambda text: 'SQL' in text and 'syntax' in text):
                    vulnerable = True
                    break
            except RequestException:
                continue

        return vulnerable

    def check_nosql_injection(self, target_url):
        vulnerable = False
        payloads = [
            {"$ne": ""},
            {"$gt": ""},
            {"$regex": ".*"}
        ]

        for payload in payloads:
            try:
                response = requests.post(target_url, json=payload)

                if response.status_code == 500:
                    vulnerable = True
                    break

                try:
                    if response.json().get("error") and "NoSQL" in response.json().get("error"):
                        vulnerable = True
                        break
                except JSONDecodeError:
                    continue
            except RequestException:
                continue

        return vulnerable

    def check_os_command_injection(self, target_url):
        vulnerable = False
        payloads = ["; uname -a", "| uname -a", "|| uname -a", "& uname -a"]

        for payload in payloads:
            try:
                injected_url = f"{target_url}?cmd={payload}"
                response = requests.get(injected_url)

                if response.status_code == 500:
                    vulnerable = True
                    break

                if "Linux" in response.text or "Darwin" in response.text:
                    vulnerable = True
                    break
            except RequestException:
                continue

        return vulnerable

    def run(self, target_url):
        sql_vulnerable = self.check_sql_injection(target_url)
        nosql_vulnerable = self.check_nosql_injection(target_url)
        os_command_vulnerable = self.check_os_command_injection(target_url)

        vulnerable = sql_vulnerable or nosql_vulnerable or os_command_vulnerable
        details = []

        if sql_vulnerable:
            details.append("The application is vulnerable to SQL injection attacks.")
        if nosql_vulnerable:
            details.append("The application is vulnerable to NoSQL injection attacks.")
        if os_command_vulnerable:
            details.append("The application is vulnerable to OS Command injection attacks.")

        return {
            "vulnerable": vulnerable,
            "plugin_name": self.plugin_name,
            "details": " ".join(details)
        }

