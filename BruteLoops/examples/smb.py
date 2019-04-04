
from smb.SMBConnection import SMBConnection
import re
import string
from random import randint,choice

def gen_client_name(min_len=5,max_len=15):
    '''
    Generate a random client name.
    '''
    
    i = randint(min_len,max_len)

    return ''.join(
                [choice(string.ascii_letters+string.digits) for n in range(32)]
            )

class SMB:

    def __init__(self, server_ip, server_name=None, server_port=445,
            client_name=None, default_domain='WORKGROUP'):
        '''
        Initialize the SMB Callback.

        server_ip - ip address of the target server
        server_name - NetBIOS name of the server (can be replaced with ip address)
        server_port - Port the SMB server is listening on
        client_name - NetBIOS name of client host
        default_domain - Default domain to use when one is not detected in the username
        '''

        self.server_ip = server_ip
        self.server_port = server_port
        self.default_domain = default_domain

        if server_name:
            self.server_name = server_name
        else:
            self.server_name = server_ip

        if client_name:
            self.client_name = client_name
        else:
            self.client_name = gen_client_name()

    def __call__(self,username,password,*args,**kwargs):
    
        # ==================
        # PARSE THE USERNAME
        # ==================
    
        # Assume domains are passed with each username in one of three formats:
            # DOMAIN/USERNAME
            # DOMAIN\USERNAME
            # USERNAME@DOMAIN

        original_username = username
    
        if re.search(r'@',username):
            username, domain = username.split('@',username)
        elif re.search(r'/',username) or re.search(r'\\|\\',username):
            domain, username = re.split(r'/|\\',username)
        else:
            domain = self.default_domain

        conn = SMBConnection(username, password, self.client_name,
                self.server_name, domain=domain, use_ntlm_v2=True,
                is_direct_tcp=True)
        outcome = conn.connect(self.server_ip, self.server_port)

        # =============
        # RETURN OUTPUT
        # =============

        if outcome:
            conn.close()
            return (1,original_username,password,)
        else:
            return (0,original_username,password,)
