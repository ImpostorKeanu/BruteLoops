from .jitter import Jitter

class Callback:
    '''
    Callback object that is callable while also implementing authentication
    jitter when required. This approach prevents the main process from
    blocking when authentication jitter is desired at the _process_ level
    instead of the main process.
    '''

    def __init__(self,callback,authentication_jitter=None):
        'Initialize the Callback object'

        # ASSERT THAT THE CALLBACK IS CALLABLE
        assert '__call__' in callback.__dir__(), (
            'callback must implement __call__'
        )

        # ASSERT THAT THE JITTER IS OF TYPE Jitter
        if authentication_jitter:
            assert authentication_jitter.__class__ == Jitter, (
                'authentication_jitter must be of type Jitter, got '\
                f'{authentication_jitter.__class__}'
            )

        self.callback = callback
        self.authentication_jitter = authentication_jitter

        # Setting a callback name attribute for logging purposes
        if hasattr(callback,'callback_name'):
            self.callback_name = getattr(callback,'callback_name')
        else: None

    def __call__(self,*args,**kwargs):
        'Call the callback, jitter if desired, and return the output'

        output = self.callback(*args, **kwargs)
        if self.authentication_jitter: self.authentication_jitter.sleep()
        return output
