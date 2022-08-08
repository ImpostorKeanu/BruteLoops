!!! warning

    - All examples assume that the execution environment is **Linux**.
    - Attack configurations should not be viewed as well-considered.
    - Authentication callbacks presented here are intentionally naive
      to clearly communicate how configuration is intended to occur.

## Basic Example

``````python
from bruteloops.models import Config
from bruteloops.brute import BruteForcer
from bruteloops.db_manager import Manager
from random import randint
from pathlib import Path

# ==================================
# DEFINE THE AUTHENTICATION CALLBACK
# ==================================

def auth_cb(username:str, password:str) -> dict:
    '''Guess the credentials. Returns valid credential output when
    username is "u5" and the password is "p2".

    Returns:
      Dictionary determining if credentials are valid.
    '''

    # Return value
    ret = dict(outcome=0)

    # Check the credentials
        # Normally you'd hit a remote service or something, here.
    if username == 'u5' and password == 'p2':
        ret['outcome'] = 1

    return ret

# =====================================
# CREATE & POPULATE THE SQLITE DATABASE
# =====================================

# Create credentials to import
spray_creds = [f'u{n}:p{n}' for n in range(1,11)]

# Initialize a Manager instance
db_file = f'/tmp/test-{randint(0,1000)}.db'
print(f'[+] db_file: {db_file}')

dbm = Manager(db_file=db_file)
dbm.manage_credentials(container=spray_creds)

# ===================================================
# CREATE CONFIG AND BRUTEFORCER AND LAUNCH THE ATTACK
# ===================================================

config = Config(
    db_file=db_file,
    authentication_callback=auth_cb,
    authentication_jitter=dict(
        min='0.2s',
        max='1s'),
    max_auth_jitter=dict(
        min='5s',
        max='20s')
)

bf = BruteForcer(config=config)
bf.launch()
Path(db_file).unlink()
``````
