
from libs.jitter import Jitter
from types import FunctionType, MethodType
import inspect

class Config:
    '''
    # Callback Configurations

    authentication_callback - called for each brute force instance
    validation_callback - callback to validate outcome of authentication_callback
    post_callback - some action to perform after the validation callback

    # Jitter Configurations

    - will be a jitter object

    authentication_jitter - jitter between authentication attempts
    max_auth_jitter - jitter between iterations

    # Logging Configurations

    - log to an sqlite database
    - log start/stop time of brute force attacks

    log_file - file to receive logs
    log_success - determine if success should be logged
    log_failure - determine if failure should be logged

    # Alert Configurations

    Alerts are things printed to stdout during execution

    alert_success - determine if success should be alerted
    alert_failure - determine if failures should be alerted
    '''

    CALLABLE_TYPES = [FunctionType, MethodType] 
    
    ### define parameters with annotations
    # each will have a list of allowed types (classes)
    def __init__(self,
            authentication_callback:CALLABLE_TYPES=None,
            validation_callback:CALLABLE_TYPES=None,
            post_callback:CALLABLE_TYPES=None,
            authentication_jitter:[Jitter]=None,
            max_auth_jitter:[Jitter]=None,
            log_file:[str]=None,
            log_success:[bool]=None,
            log_failure:[bool]=None,
            alert_success:[bool]=None,
            alert_failure:[bool]=None):

        ### get the current stack frame
        frame = inspect.currentframe()

        ### get the string name of the current function
        function = BruteForcer.config.__dict__[
            inspect.getframeinfo(frame).function
        ]

        ### get annotations from argspec
        annotations = inspect.getfullargspec(
            function
        ).annotations

        ### detect invalid argument types
        invalid = {}

        # iterate over each annotation item
         # param is the parameter string
         # used to pull the argument from the dict returned by locals()
         # valid_types is the value of the current annotation
         # set to a list of valid types

        # alternatively, could have used inspect.getargvalues(frame)
        _locals = locals()
        for param,valid_types in annotations.items():

            # get the value of the current parameter (argument)
            arg=_locals[param]

            # test if the class of the argument is valid by checking
             # if it resides in the list of valid classes
            if arg.__class__ not in valid_types:
                invalid[param] = {
                    'type_provided':arg.__class__,
                    'value_provided':arg,
                    'types_allowed':valid_types,
                    'error_message': f'Invalid type provided for {param}.'\
                        f' Expected: {valid_types}. Received: {arg.__class__}'
                }
