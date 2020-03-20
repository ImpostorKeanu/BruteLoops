#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search
import requests

FAIL_VALUE = '"errorCode":"E0000004","errorSummary":"Authentication ' \
        'failed"' 

class Okta:

    def __init__(self, url, cookies_url, referer_url=None,
            proxies={}, headers={}, verify_ssl=False):
        '''
        # Notes

        ## cookies_url parameter

        The argument to this parameter should be the full URL for the POST request
        that returns cookies for the authentication process.
        '''

        self.url = url
        self.cookies_url = cookies_url
        self.referer_url = referer_url
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password,*args,**kwargs):

        # =====================
        # CRAFT THE COOKIES URL
        # =====================

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

        headers = self.headers

        if self.referer_url:
            headers['Referer'] = referer_url

        # =============================
        # BUILD SESSION AND GET COOKIES
        # =============================

        session = requests.Session()
        session.get(cookies_url,headers=headers)

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
