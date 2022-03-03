'''This module contains classes to produce meaningful error messages.
'''

from functools import wraps
from inspect import signature, Parameter

def error(f):
    '''Decorator to assist with formatting and returning error
    messages.

    `error` expects the decorated function to return a tuple as
    specified in the below notes. It then generates an error
    from the `ErrorClass` and processes `StrMessageTemplate`
    using `str.format` while passing all keyword arguments
    such that they will be rendered in the final error message.

    Notes:

        Decorated functions are expected to satisfy the following
          criteria:

        1. Along with any parameters required by the decorated
          function, the function signature must contain
          `*args, **kwargs`.
        2. The `extra` keyword argument is used to suffix any
          additional information to the error message. This
          aims to be a convenience to avoid complex format
          string templates.
        3. The return value must be a tuple in the form:
          `(ErrorClass, StrMessageTemplate)`
    '''

    @wraps(f)
    def wrapper(*args, **kwargs) -> Error:

        # ===========================
        # GET FUNCTION/CALL VARIABLES
        # ===========================

        # Call the decorated function to receive the
        # error class and format string
        error_class, fmsg = f(*args, **kwargs)

        # Get the method signature and parameters from
        # the decorated function
        sig = signature(f)
        params = sig.parameters
        args = list(args)

        # Gather format arguments from the decorated function's
        # signature to form a dictionary.
        fargs, extra = {}, None
        for name, param in params.items():

            # Ignore strictly positional/keyword arguments
            if param.kind is not Parameter.POSITIONAL_OR_KEYWORD:
                continue

            if name in kwargs:

                # Pull as a keyword argument
                fargs[name] = kwargs[name]

            else:

                # Assume it's a positional value
                fargs[name] = args.pop(0)

        # Append the "extra" tag when it isn't found in
        # the format string template.
        if 'extra' in kwargs:

            # Append the extra template.
            if fmsg.find('{extra}') == -1:
                fmsg += ' ({extra})'

            # Capture extra detail.
            fargs['extra'] = str(kwargs['extra'])

        # ===================================
        # PRODUCE AND RETURN THE ERROR OBJECT
        # ===================================

        try:

            # Return the error message when things go
            # right
            return error_class(fmsg.format(**fargs))

        except Exception as e:

            # Handle when things go wrong
            raise Error.failedErrorFormatting(str(e))

    return wrapper

class Error(Exception):
    '''Generic error class.
    '''

    @staticmethod
    def failedErrorFormatting(msg):
        '''Failed to properly format the error string.
        '''

        return Error(f'Failed to format error message: {msg}')

class TimezoneError(Error):
    '''Timezone errors.
    '''

    @staticmethod
    @error
    def invalidTZ(tz:str, *args, **kwargs):
        '''An invalid timezone string name has been supplied.
        '''

        return TimezoneError, 'Invalid timezone supplied: {tz}'

class LoggingError(Error):
    '''Logging errors.
    '''

    @staticmethod
    @error
    def invalidLevelName(level:str, *args, **kwargs):
        '''An invalid string for logging levels was supplied.
        '''

        return LoggingError, 'Invalid logging level supplied: {level}'
