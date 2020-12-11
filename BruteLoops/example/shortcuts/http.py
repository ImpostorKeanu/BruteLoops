from BruteLoops.example.module import Module
import warnings
from urllib.parse import urlparse
import re
from BruteLoops.db_manager import csv_split

warnings.filterwarnings('ignore')

DEFAULT_USER_AGENT = 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 ' \
        'Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko' \
        ') Chrome/85.0.4183.121 Mobile Safari/537.36'

class HTTPModule(Module):

    def __init__(self, url:'required:True,type:str,help:URL to target',
            proxies:'required:False,type:str,help:Space delimited ' \
                    'proxies to use. Each value should be in URL ' \
                    'format, e.g. https://myproxy.ninja'=None,
            headers:'required:False,type:str,help:Space delimited ' \
                    'Static HTTP headers to pass along to each ' \
                    'request.,nargs:+'=None,
            verify_ssl:'required:False,type:bool,help:Verify SSL ' \
                    'cert'=False,
            user_agent:'required:False,type:str,help:User-agent ' \
                    'string'=DEFAULT_USER_AGENT, *args, **kwargs):
        '''Update the __init__ method of a class with a signature for common
        arguments that are passed to the Requests module, facilitating rapid
        development of brute force modules.

        WARNING: This is an method decorator expecting the initial argument
        to be "self"
        '''

        self.url = url

        # ===================
        # HANDLE HTTP PROXIES
        # ===================

        if proxies and not isinstance(proxies,list):
            raise ValueError('Invalid proxies argument. Must be list')

        proxies = proxies if proxies != None else []

        self.proxies = {}
        for proxy in proxies:
            try:
                url = urlparse(proxy)
                self.proxies[url.scheme]=url.netloc
            except Exception as e:
                raise ValueError('Invalid proxy value supplied')

        # ===================
        # HANDLE HTTP HEADERS
        # ===================

        headers = headers if headers != None else {}

        self.headers = {}
        for header in headers:
            try:
                key, value = csv_split(header)
                self.headers[key] = value.strip()
            except Exception as e:
                raise ValueError(
                        f'Invalid header supplied: {header}'
                    )

        # ========================
        # OTHER INSTANCE VARIABLES
        # ========================

        self.user_agent = user_agent if user_agent else DEFAULT_USER_AGENT        
