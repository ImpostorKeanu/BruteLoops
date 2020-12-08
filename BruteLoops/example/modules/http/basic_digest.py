#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests
from requests.auth import HTTPDigestAuth as HDA
from BruteLoops.example.module import Module as BLModule

class Module(BLModule):

    # String found to match any of those inserted here will be
    # replaced with a string literal value of ''
    blank_signatures = []

    name = 'http.basic_digest'
    description = brief_description = 'Generic HTTP basic digest auth'

    def __init__(self, url:'required:True,type:str,help:URL to target',
            proxies:'required:False,type:str,help:Proxies to use'={},
            headers:'required:False,type:str,help:Static HTTP headers'={},
            verify_ssl:'required:False,type:bool,help:Verify SSL cert'=False):

        self.url = url
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password,*args,**kwargs):

        if self.blank_handler(username): username = ''
        if self.blank_handler(password): password = ''

        # http://docs.python-requests.org/en/master/user/authentication/
        resp = requests.get(self.url,
                auth=HDA(username,password),
                headers=self.headers,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies)
    
        # verify credentials and return outcome
        if resp.status_code == 401:
            return (0, username, password,)
        else:
            return (1, username, password,)
    
    def blank_handler(self,value):

        if value in self.__class__.blank_signatures:
            return True
        else:
            return False
