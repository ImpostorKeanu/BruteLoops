
# NOTE: This module relies on the pysmb package
from smb.SMBConnection import SMBConnection
import re
import string
from random import randint,choice
from BruteLoops.example.module import Module as BLModule

def gen_client_name(min_len=5,max_len=15):
    '''Generate a random client name.
    '''
    
    i = randint(min_len,max_len)

    return ''.join(
                [choice(string.ascii_letters+string.digits) for n in range(32)]
            )

class Module(BLModule):
    '''Defining the callback
    '''

    name = 'SMB' # For logging
    brief_description = description = 'Target a single SMB server'

    def __init__(self,
            server_ip:'required:True,type:str,help:IP address of the SMB server ' \
                    'authenticate against',
            server_name:'required:False,type:str,help:Server hostname'=None,
            server_port:'required:False,type:int,help:Port of SMB service'=445,
            client_name:'required:False,type:str,help:Client name'=None,
            default_domain:'required:False,type:str,help:Default WORKGROUP name when ' \
                    'domain isn\'t provided in a username'='WORKGROUP'):
        '''Initialize the SMB Callback.
        '''

        self.server_ip = server_ip
        self.server_port = server_port
        self.default_domain = default_domain

        self.server_name = server_name if server_name else server_ip
        self.client_name = client_name if client_name else \
                gen_client_name()

    def __call__(self, username, password, *args, **kwargs):
    
        # ==================
        # PARSE THE USERNAME
        # ==================
    
        # Assume domains are passed with each username in one of three formats:
            # DOMAIN/USERNAME
            # DOMAIN\USERNAME
            # USERNAME@DOMAIN

        original_username = username
    
        if re.search(r'@',username):
            username, domain = username.split('@')
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
