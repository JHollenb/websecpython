#! /home/siuser/repos/owasp/venv/bin/python
# Main Program (main.py)

import argparse
import logging

# Import your plugins here
import plugins.broken_access_control_plugin as broken_access_control_module
import plugins.cryptographic_failures_plugin as cryptographic_failures_module
import plugins.injection_plugin  as im
import plugins.security_misconfiguration_plugin  as smm
import plugins.vulnerable_component_plugin  as vcm
import plugins.authentication_plugin  as am
import plugins.integrity_plugin  as integritym
import plugins.ssrf_plugin as ssrf


import threading
import queue

class VulnerabilityScanner:
    def __init__(self, target_url, plugins, threads=4):
        self.target_url = target_url
        self.plugins = plugins
        self.threads = threads
        self.queue = queue.Queue()
        self.results = []

    def scan(self):
        for plugin in self.plugins:
            self.queue.put((plugin, self.target_url))

        for i in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()

        self.queue.join()
        return self.results

    def worker(self):
        while not self.queue.empty():
            try:
                item = self.queue.get(timeout=1)
                plugin, target_url = item
                result = plugin.run(target_url)
                if result and result["vulnerable"]:
                    self.results.append(result)
                self.queue.task_done()
            except queue.Empty:
                break


def available_plugins():
    return {
        "BrokenAccessControl": broken_access_control_module.BrokenAccessControlPlugin,
        "CryptographicFailures": cryptographic_failures_module.CryptographicFailuresPlugin,
        "Injection": im.InjectionPlugin,
        "Security-Misconfiguration": smm.SecurityMisconfigurationPlugin,
        "VulnerableOutdatedComponents": vcm.VulnerableOutdatedComponentsPlugin,
        "Authentication": am.AuthenticationPlugin,
        "Integrity": integritym.IntegrityPlugin,
        "SSRF": ssrf.SSRFPlugin
    }


# Setup the argparse
parser = argparse.ArgumentParser(description="Vulnerability Scanner")
parser.add_argument("url", help="Target URL to scan")
parser.add_argument("--plugin", choices=list(available_plugins().keys()), action="append", help="Select the plugin(s) to use")
parser.add_argument("--all", action="store_true", help="Run all available vulnerability checks")
parser.add_argument("--threads", type=int, default=4, help="Number of threads to use")
args = parser.parse_args()

# Configure logging
logging.basicConfig(filename="vulnerability_log.txt", level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

# Instantiate plugins based on argparse selections
selected_plugins = []

if args.all:
    for plugin_class in available_plugins().values():
        selected_plugins.append(plugin_class())
else:
    if args.plugin:
        for plugin_name in args.plugin:
            if plugin_name in available_plugins():
                selected_plugins.append(available_plugins()[plugin_name]())

# Run the Vulnerability Scanner with the selected plugins
scanner = VulnerabilityScanner(args.url, selected_plugins, args.threads)
scan_results = scanner.scan()

print(scan_results)
