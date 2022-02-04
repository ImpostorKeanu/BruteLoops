from BruteLoops import data
from BruteLoops.example.module import Module
import warnings
from urllib.parse import urlparse
import re
from BruteLoops.db_manager import csv_split
from functools import wraps
from random import randint
from inspect import getargspec
from logging import getLogger,INFO
import pdb

brute_logger = getLogger('BruteLoops.example.shortcuts.http')

warnings.filterwarnings('ignore')
PROXY_FORMAT='<http|https>:<Proxy URI>'
PROXY_EXAMPLE='https:http://127.0.0.1:8080'
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 ' \
        'Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko' \
        ') Chrome/85.0.4183.121 Mobile Safari/537.36'

# Application protocols are only http and https
PROXY_RE= re.compile('^(?P<app_proto>(http|https)?):(?P<proxy_uri>.+)', re.I)

# Requests supports only http, https, and socs5 proxies
PROXY_URI_RE=re.compile('^(http|https|socks5)://(.+):[0-9]{1,5}')

def handleUA(f):
    '''A decorator to handle user agent strings, supporting a
    randomization capability. If the string is "RANDOM", then
    a random value will be selected from BruteLoops.data.UAS.
    See that module to learn where random values originate
    from.
    '''

    @wraps(f)
    def wrapper(self, username, password, *args, **kwargs):

        if self.randomize_ua:

            # ======================
            # GET A RANDOM UA STRING
            # ======================

            # loadUserAgents actually only loads when UAS is
            # empty or the force argument is set to True.
            data.loadUserAgents()

            if data.UAS:

                # Get a value from UAS
                self.user_agent = data.UAS[randint(0, len(data.UAS)-1)]

        # Set the header value
        self.headers['User-Agent'] = self.user_agent

        return f(self, username, password, *args, **kwargs)

    return wrapper

class HTTPModule(Module):

    # TODO
    '''Convert this monstrosity of an idea with strings embedded in
    the function annotations to a dictionary. I was clearly high when
    this design decision was made.
    '''

    def __init__(self,
            url:'required:True,'
                'type:str,'
                'help:URL to target',
            proxies:'required:False,'
                'type:str,'
                'nargs:+,'
                'help:Space delimited proxies to use. Each value '
                'should be in URL format prefixed by the proxy protoco'
                'l. If you\'re proxying an HTTPS application through B'
                'urp, for instance, then you would need to prefix the '
                'target application URL with "http:", e.g. http:https:'
                '//myproxy.ninja'=None,
            headers:'required:False,'
                'type:str,'
                'nargs:+,'
                'help:Space delimited static HTTP headers to pass alo'
                'ng to each request. Note that each header must be fo'
                'rmatted as follows: "Header: value". The ": " sequen'
                'e is used to identify the break between the header a'
                'nd the value. Example > X-Forwarded-For: localhost' \
                    =None,
            verify_ssl:'required:False,'
                'type:bool,'
                'help:Verify SSL cert'=False,
            user_agent:'required:False,'
                'type:str,'
                'help:User-agent string'=DEFAULT_USER_AGENT,
            allow_redirects:'required:False,'
                'type:bool,'
                'help:Determine if requests should follow redirects.'\
                    =False,
            *args, **kwargs):
        '''Update the __init__ method of a class with a signature for common
        arguments that are passed to the Requests module, facilitating rapid
        development of brute force modules.

        WARNING: This is an method decorator expecting the initial argument
        to be "self"
        '''

        self.url = url
        self.proxies = {}
        self.headers = {}
        self.user_agent = user_agent
        self.verify_ssl = True if verify_ssl else False
        self.allow_redirects = True if allow_redirects else False

        # ===================
        # HANDLE HTTP PROXIES
        # ===================
        proxies = proxies if proxies != None else []

        # Ensure that the proxies are being passed as a list
        # this is handled by argparse as "nargs:+," in the function
        # annotations.
        if proxies and not isinstance(proxies,list):
            raise ValueError('Invalid proxies argument. Must be list.')

        for proxy in proxies:

            proxy = proxy.lower()

            # Parse the proxy configuration via capture group
            match = re.match(PROXY_RE, proxy)

            # Raise a ValueError if an improperly formatted value is supplied
            if not match:

                raise ValueError(
                    'Proxies must be supplied in the following format: '
                    '{}, e.g. {}'.format(
                        PROXY_FORMAT,PROXY_EXAMPLE)
                )

            # Prepare the value dictionary
            gd = match.groupdict()

            # Ensure the proxy URI is valid 
            if not re.match(PROXY_URI_RE, gd['proxy_uri']):

                raise ValueError(
                    'Invalid destination URL provided for proxy: "{}". '
                    'Valid proxy configuration format: {}, eg {}'.format(
                        gd['proxy_uri'],PROXY_FORMAT,PROXY_EXAMPLE)
                )

            try:

                self.proxies[gd['app_proto']]=gd['proxy_uri']

            except Exception as e:

                raise ValueError('Invalid proxy value supplied.')

        # ===================
        # HANDLE HTTP HEADERS
        # ===================
        '''Parse a list of HTTP headers from the arguments.

        Each header is expected to be formatted as:

        <HeaderKey>: <HeaderValue>

        Note that the colon+space ": " value serves as the
        actual split delimiter.
        '''

        headers = headers if headers != None else {}

        for header in headers:
            try:
                key, value = header.split(': ', 1)
                self.headers[key] = value.strip()
            except Exception as e:
                raise ValueError(
                        f'Invalid header supplied: {header}'
                    )

        # ========================
        # OTHER INSTANCE VARIABLES
        # ========================

        self.randomize_ua = False
        if self.user_agent == 'RANDOM':
            self.randomize_ua = True
            self.headers['User-Agent'] = DEFAULT_USER_AGENT 

    @property
    def request_args(self):
        '''Return instance variables intended to be used as arguments
        to the requests library as a dictionary, facilitating expansion
        via `**` operator.

        Example:

        ```
        resp = requests.post(
            **self.request_args,
            data=payload)
        ```
        '''

        return {'url':self.url,
            'headers':self.headers,
            'proxies':self.proxies,
            'allow_redirects':self.allow_redirects,
            'verify':self.verify_ssl}
