#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests

class Okta:

    def __init__(self, url, cookies_url, proxies={}, headers={}, verify_ssl=False):

        self.url = url
        self.cookies_url = cookies_url
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password,*args,**kwargs):

        # =============================
        # BUILD SESSION AND GET COOKIES
        # =============================

        session = requests.Session()
        session.get(self.cookies_url)

        # ===================================
        # BUILD REQUEST DATA AND MAKE REQUEST
        # ===================================

        # post data
        data = {
            "password":password,
            "username":username,
            "options":
            {
                "warnBeforePasswordExpired":True,
                "multiOptionalFactorEnroll":True
            }
        }
    
        # make the request
        resp = session.post(self.url,
                json=data,
                headers=self.headers,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies)

        # ===================================
        # CHECK FOR SUCCESSFUL AUTHENTICATION
        # ===================================
    
        # verify credentials and return outcome
        if resp.status_code == 401:
            return [0, username, password]
        else:
            return [1, username, password]
