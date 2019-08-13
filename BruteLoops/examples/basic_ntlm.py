#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests
from requests_ntlm import HttpNtlmAuth

class BasicNTLM:

    def __init__(self, url, proxies={}, headers={}, verify_ssl=False):

        self.url = url
        self.proxies = proxies
        self.verify_ssl = verify_ssl
        self.headers = headers

    def __call__(self,username,password,*args,**kwargs):
    
        # make the request
        resp = requests.get(self.url,
                    headers=self.headers,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    auth=HttpNtlmAuth(
                        username,
                        password
                    )
                )

        # verify credentials and return outcome
        if resp.status_code == 401:
            return [0, username, password]
        else:
            return [1, username, password]
