from re import search
import requests
import warnings
from urllib.parse import unquote
warnings.filterwarnings('ignore')

class ADFS():

    def __init__(self,url,headers={},proxies={},verify_ssl=False,timeout=5):
        '''
        url - Should contain the full url, including query string, that will be
        sent to the server during authentication. I generally use the one generated
        by Microsoft after being redirected to a federated ADFS server.
        '''
        # Unquote the URL to avoid double-quoting the query string
        self.url = unquote(url)
        self.headers = headers
        self.proxies = proxies
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def __call__(self,username,password):

        # post data
        data = {
            'UserName':username,
            'Password':password,
            'AuthMethod':'FormsAuthentication',
        }
    
        try:
        
            # make the request
            resp = requests.post(
                self.url,
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
