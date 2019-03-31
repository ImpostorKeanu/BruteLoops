from BruteLoops.jitter import Jitter
from BruteLoops.brute import Horizontal
from BruteLoops.config import Config

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
def fake(username, password):
    'Fake authentication function to serve as a basic example'

    if username == 'administrator' and password == 'P@ssw0rd':
        return [1,username,password]
    else:
        return [0,username,password]

config = Config()
config.authentication_callback = fake   # Function/object/callbale used to determine of credentials are valid
                                        # Will receive arguments as: config.authenticaiton_callback(usernam,password)
                                        #
                                        # Expected to return: (authentication_outcome,username,password)
                                        # authentication_outcome should be an integer value, where anything greater
                                        # than 0 indicates successful authentication
# ============================
# AUTHENTICATION CONFIGURATION
# ============================
config.process_count = 8            # Use 8 processes for authentication
config.max_auth_tries = 3           # Allow up to three simultaneous authentication attempts per user
#config.stop_on_valid = True        # Uncomment this to halt authentication after recover of a single account

# ====================
# JITTER CONFIGURATION
# ====================
config.authentication_jitter = Jitter(min='2s',max='3s') # Sleep for a small window of time between auth attempts
config.max_auth_jitter = Jitter(min='10s',max='15s')     # Sleep for an extended period of times after max_auth_tries

# ====================
# OUTPUT CONFIGURATION
# ====================

config.db_file = 'testdb.sqlite'    # REQUIRED: Database to write usernames/passwords

# NOTE: Logging is entirely optional!

# LOGGING LEVELS
config.log_valid = True             # Log authentication records that appear to be valid
#config.log_invalid = True          # Log invalid authentication attempts (verbose)
config.log_general = True           # Log general events (even more verbose)

# LOG DESTINATIONS
config.log_stdout = True            # Log to stdout
config.log_file = 'testlog.txt'     # Log to a file

# ===============================
# EXCEPTION HANDLER CONFIGURATION
# ===============================
config.exception_handlers={KeyboardInterrupt:handle_keyboard_interrupt}

# ==========================
# VALIDATE THE CONFIGURATION
# ==========================

# Always validate the configuration.
config.validate()

try:

    print('Initializing attack')
    bf = Horizontal(config)
    bf.launch(usernames='testusers.txt',passwords='testpasswords.txt')
    print('Brute force attack finished')
    
except Exception as e:

    print()
    print('Unhandled exception occurred.\n')
    print(e)
    print(e.with_traceback())
    print(e.__traceback__.__dir__())
    print(e.__traceback__.tb_lineno)
    print()
    print()
