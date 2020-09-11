from sys import exit

def get_user_input(m):
    '''
    Simple input loop expecting either a ```y``` or ```n``` response.
    '''

    uinput = None
    while uinput != 'y' and uinput != 'n':
        uinput = input(m)

    return uinput

