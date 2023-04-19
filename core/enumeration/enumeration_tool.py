#!/home/siuser/repos/websecpython/venv/bin/python3
import socket
import dns.resolver
import json
import requests
from bs4 import BeautifulSoup
from ipwhois import IPWhois
from nmap import PortScanner
import tldextract
import argparse
from tqdm import tqdm
import concurrent.futures


class TargetEnumeration:
    def __init__(self, domain, wordlist, threads):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads

    def resolve_subdomain(self, subdomain):
        try:
            full_subdomain = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(full_subdomain, "A")
            return full_subdomain
        except (dns.resolver.NXDOMAIN, dns.name.EmptyLabel):
            return None

    def get_subdomains(self):
        with open(self.wordlist, 'r') as f:
            subdomains_list = [line.strip() for line in f if line.strip()]

        found_subdomains = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {executor.submit(self.resolve_subdomain, subdomain): subdomain for subdomain in subdomains_list}
            for future in tqdm(concurrent.futures.as_completed(future_to_subdomain), total=len(subdomains_list), desc='Enumerating subdomains', unit='subdomain'):
                result = future.result()
                if result:
                    found_subdomains.append(result)

        return found_subdomains

    def get_ips(self, subdomains):
        ip_addresses = []
        for subdomain in subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                ip_addresses.append(ip)
            except socket.gaierror:
                continue
        return ip_addresses

    def get_ports(self, ip, port_range=(1, 1024)):
        scanner = PortScanner()
        open_ports = []
        for port in range(*port_range):
            result = scanner.scan(hosts=ip, arguments=f'-p {port} --open')
            if result['scan'][ip]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
        return open_ports

    def get_web_services(self, url):
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        headers = json.loads(json.dumps(dict(response.headers)))
        server = headers.get('Server', '')
        technologies = []

        # Identify technologies using Wappalyzer API
        wappalyzer_api_key = 'YOUR_WAPPALYZER_API_KEY'
        wappalyzer_url = f'https://api.wappalyzer.com/lookup/v2/?url={url}&api_key={wappalyzer_api_key}'
        wappalyzer_response = requests.get(wappalyzer_url)
        if wappalyzer_response.status_code == 200:
            wappalyzer_data = wappalyzer_response.json()
            for tech in wappalyzer_data['technologies']:
                technologies.append(tech['name'])

        return {
            'title': soup.title.string if soup.title else '',
            'server': server,
            'technologies': technologies
        }


    def enumerate(self):
        subdomains = self.get_subdomains()
        ips = self.get_ips(subdomains)
        results = []

        for index, subdomain in enumerate(tqdm(subdomains, desc='Processing targets', unit='target')):
            url = f"http://{subdomain}"
            open_ports = self.get_ports(ips[index])
            web_services = self.get_web_services(url)

            results.append({
                'subdomain': subdomain,
                'ip': ips[index],
                'ports': open_ports,
                'web_services': web_services
            })

        return results

def parse_arguments():
    parser = argparse.ArgumentParser(description='Target Enumeration Tool')
    parser.add_argument('domain', type=str, help='Domain to enumerate')
    parser.add_argument('-w', '--wordlist', type=str, default='subdomains.txt', help='Path to subdomains wordlist')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads to use for subdomain enumeration')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()
    domain = args.domain
    wordlist = args.wordlist
    threads = args.threads
    enumeration = TargetEnumeration(domain, wordlist, threads)
    results = enumeration.enumerate()
    print(json.dumps(results, indent=2))
