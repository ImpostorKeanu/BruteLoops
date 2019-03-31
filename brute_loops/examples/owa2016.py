#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests

class OWA2016:

    def __init__(self, url, proxies={}, headers={}, verify_ssl=False):

        self.url = url
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password):

    
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
        resp = requests.post(url,
                data=data,
                headers=headers,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=proxies)
    
        # verify credentials and return outcome
        if resp.status_code == 302 and resp.headers['Location'] and (
            search(r'auth\/logon\.aspx\?', resp.headers['Location'])):
            return [0, username, password]
        else:
            return [1, username, password]
