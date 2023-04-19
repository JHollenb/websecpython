# plugins/base_plugin.py

import logging

class BasePlugin:
    def __init__(self, name):
        self.name = name

    def log_vulnerability(self, message):
        logging.warning("{} vulnerability found: {}".format(self.name, message))

    def run(self, url):
        raise NotImplementedError("The 'run' method should be implemented in each plugin class.")

