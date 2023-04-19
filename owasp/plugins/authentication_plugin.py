import requests
from bs4 import BeautifulSoup

class AuthenticationPlugin:

    def __init__(self):
        self.name = "Authentication Plugin"
        self.description = "This plugin checks for authentication and session management issues."

    def run(self, target_url):
        issues = []
        issues.extend(self.check_login_page(target_url))
        return issues

    def check_login_page(self, target_url):
        issues = []
        login_page_url = f"{target_url}/login"
        try:
            response = requests.get(login_page_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form')
                if form:
                    issues.extend(self.analyze_login_form(form))
        except requests.exceptions.RequestException as e:
            issues.append(f"Error while trying to access the login page: {e}")
        return issues

    def analyze_login_form(self, form):
        issues = []
        password_inputs = form.find_all('input', {'type': 'password'})
        if len(password_inputs) == 0:
            issues.append("No password input field found in the login form.")
        return issues

    def get_url_scheme(self, url):
        return url.split(':')[0]

    def is_https(self, url):
        return self.get_url_scheme(url) == 'https'

# Sample usage:
# plugin = AuthenticationPlugin()
# issues = plugin.run('http://example.com')
# for issue in issues:
#     print(issue)

