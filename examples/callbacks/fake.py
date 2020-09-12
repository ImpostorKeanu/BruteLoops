from time import sleep
from random import randint

def fake(username, password):
    'Fake authentication function to serve as a basic example'
   
    # sleep(randint(0,5))
    if username == 'superadmin' and password == 'password!':
        return [1,username,password]
    else:
        return [0,username,password]
