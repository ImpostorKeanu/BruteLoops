class Fake:
    '''Fake authentication callback for testing purposes. Accepts a
    username and password value during initialization that will be
    compared against future authentication calls.

    This effectively gives developers a mechanism by which to emulate
    an authentication event during tool development.
    '''

    def __init__(self, username, password):
        '''Initialize the Fake object.

        - username - username value
        - password - password value
        '''

        self.username = username
        self.password = password

    def __call__(username, password):
        'Check the provided username and password values'
   
        if username == self.username and password == self.password:
            return [1,username,password]
        else:
            return [0,username,password]
