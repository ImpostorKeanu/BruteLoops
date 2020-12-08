from BruteLoops.example.module import Module as BLModule

# ==================
# BUILD THE CALLBACK
# ==================

class Module(BLModule):
    '''Fake authentication callback for testing purposes. Accepts a
    username and password value during initialization that will be
    compared against future authentication calls.

    This effectively gives developers a mechanism by which to emulate
    an authentication event during tool development.
    '''

    name = 'Fake'
    description = brief_description = 'Fake authentication module for ' \
            'training/testing'

    def __init__(self, # Use function annotations to describe parameters
            username:'required:True,type:str,help:Username to check against',
            password:'required:True,type:str,help:Password to check against'):
        '''Initialize the Fake object.

        - username - username value
        - password - password value
        '''

        self.username = username
        self.password = password

    def __call__(self, username, password):
        'Check the provided username and password values'
   
        if username == self.username and password == self.password:
            return [1,username,password]
        else:
            return [0,username,password]
