#!/usr/bin/env python3

from BruteLoops.jitter import Jitter
from BruteLoops.brute import Horizontal
from BruteLoops.config import Config
from BruteLoops.logging import GENERAL_EVENTS,logging

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

config = Config() # Initialize a configuration object
config.authentication_callback = fake # Set the authentication callback
                                     
# ============================
# AUTHENTICATION CONFIGURATION
# ============================
config.process_count = 8 # Maximum number of processes to use 
config.max_auth_tries = 1 # Max number of auth attempts before sleeping
config.stop_on_valid = True # Stop after valid credentials are recovered

# ====================
# JITTER CONFIGURATION
# ====================
config.authentication_jitter = Jitter(min='20s',max='25s') 
config.max_auth_jitter = Jitter(min='45m',max='50m')     

# ====================
# OUTPUT CONFIGURATION
# ====================
config.db_file = 'test_brute.sqlite'    

# LOGGING LEVELS # Optional
config.log_valid = True             
config.log_invalid = True          
config.log_general = True         

# LOG DESTINATIONS # Also optional
config.log_stdout = True         
config.log_file = 'brute_log.txt'

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
        usernames=['admin','administrator','super-admin'],
        passwords=['Password1','Password#1','Password1!','Password123',
            'Spring2019!','Summer2019!','Winter2018!']
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
