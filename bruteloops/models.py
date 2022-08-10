'''This module defines Pydantic types that are used to enforce
input validation for implementing programs.
'''

import inspect
import datetime
import time
import re
from .enums import *
from .jitter import *
from .brute_time import BruteTime
from .db_manager import Session
#from .callback import Callback
from .errors import BreakerTrippedError
from logging import Logger
from . import logging as BLogging
from pydantic import (
    BaseModel,
    Field,
    constr,
    validator,
    FilePath,
    Extra)
from typing import (
    Any,
    List,
    Union,
    Optional,
    Callable,
    Type,
    TypeVar)
from functools import wraps
from random import uniform

EXCEPT_TYPES = (Exception, BaseException,)
EJP = EMPTY_JITTER_PAT = re.compile('^(0(\.0+)?(s|m|h)|None)$')

def is_exception(t) -> bool:
    '''Ensure t is an Exeception instance/subtype.

    Returns:
        True when t is an Exception instance/subtype.

    Raises:
        TypeError: when t is not a subtype of Exception.
    '''

    # Handle types, i.e. classes
    if isinstance(t, type):
        if not issubclass(t, EXCEPT_TYPES):
            raise TypeError(f'{t} ({type(t)}) is not a subclass of Exception')

    # Handle Exception instances
    elif not isinstance(t, EXCEPT_TYPES):
        raise TypeError(f'{t} ({type(t)}) is not an Exception instance.')

    return True

def check_exceptions(*kwargs:List[str]):
    '''Ensure that each kwarg maps to one or more Exception
    instances/subtypes.
    '''

    # target kwargs
    tkwargs = [k for k in kwargs]

    def outer(f):
        '''Obtain the decorated function's signature and ensure
        that kwarg is a known parameter.

        Raises:
          - RuntimeError when kwarg is not a known function
            parameter.
        '''

        # Obtain the signature
        sig = inspect.signature(f)
        skeys = sig.parameters.keys()

        # Ensure all kwargs
        for k in tkwargs:

            if not k in skeys:
    
                raise RuntimeError(
                    f'Decorated function {f.__name__} does not have '
                    f'a {k} parameter.')

        @wraps(f)
        def inner(*args, **kwargs):
            '''Bind arguments to the signature and ensure that each
            kwarg supplied to the decorator maps to an Exception
            object.

            Raises:
              - TypeError non-exceptions are supplied.
            '''

            # Bind arguments to the signature
            try:
                bound = sig.bind(*args, **kwargs)
            except TypeError:
                return f(*args, **kwargs)

            # ====================
            # CHECK ARGUMENT TYPES
            # ====================

            for k in tkwargs:

                if k in bound.arguments:
                    if isinstance(bound.arguments[k], list):
                        for e in bound.arguments[k]:
                            is_exception(e)
                    else:
                        is_exception(bound.arguments[k])

            # Executed the decorated function
            return f(*args, **kwargs)

        return inner

    return outer

def jitter_str_to_float(s:str, field_name:str) -> float:
    '''Convert a jitter string to a float value for maths.

    Returns:
      Float value representing the number of seconds derived
        from s.

    Raises:
      ValueError: when an improperly formatted s is supplied.
    '''

    match = JitterTime.validate_time(s)

    if not match:

        raise ValueError(
            f'{field_name} is an invalid format: {s}'
        )

    return JitterTime.conv_time_match(match.groupdict())

class Jitter(BaseModel, extra=Extra.allow):
    '''Jitter objects are used to determine the amount of time to
    wait between authentication attempts and after the lockout
    threshold is met.
    '''

    min: constr(regex=JITTER_RE)
    'Minimum period of time to sleep.'

    max: constr(regex=JITTER_RE)
    'Maximum period of time to sleep.'

    @validator('min','max')
    def val_attr(cls, v, field, values):

        jt = jitter_str_to_float(v, field.name)

        if field.name == 'max':
            min = values.get('min')
            if not min or (min > jt):
                raise ValueError(
                    'Jitter minimum must be <= maximum. Got: '
                    f'{min} >= {jt}')

        return jt

    def __init__(self, min, max, **kwargs):
        '''Override __init__ and capture the original minimum and
        maximum for future reference.
        '''

        super().__init__(min=min, max=max, **kwargs)
        self.orig_min = min
        self.orig_max = max

    def __str__(self):
        '''Return a formatted string.
        '''

        return f'<Jitter(min="{self.orig_min}", max="{self.orig_max}")>'

    def sleep(self):
        '''Make the current process sleep for a given period of time
        based on the jitter configurations.
        '''

        time.sleep(
            self.get_jitter_duration()
        )

    def get_jitter_duration(self):
        '''Return a floating point number in the range specified for
        jitter time.
        '''

        return uniform(self.min, self.max)

    def get_jitter_future(self, current_time=None):
        
        current_time = current_time if current_time else \
            BruteTime.current_time()

        return current_time + self.get_jitter_duration()

class Blackout(BaseModel):

    start: datetime.time
    'Time when blackout period should begn.'

    stop: datetime.time
    'Time when blackout perioud should end.'

    def __str__(self):

        start = self.start.strftime('%H:%M:%S')
        stop = self.stop.strftime('%H:%M:%S')

        return f'<Blackout(start="{start}" stop="{stop}")>'

class ExceptionHandler(BaseModel, arbitrary_types_allowed=True):
    '''Instances are used to bind functions to an exception_class,
    allowing the control loop to handle arbitrary exceptions.

    Notes:
        - Breakers are always engaged before exception handlers.
    '''

    exception_class: Type[BaseException]
    'Exception class to handle.'

    handler: Callable[[BaseException], None]
    'Callback to apply to the exception.'

class Output(BaseModel, arbitrary_types_allowed=True):
    '''Model that validates outputs from authentication callbacks.'''

    outcome: GuessOutcome
    'Guess outcome.'

    username: str
    'Username that was guessed.'

    password: str
    'Password that was guessed.'

    actionable: bool = True
    ('Determines if the username is still actionable, i.e. '
    'removed/disabled from further guesses.')

    events: List[str] = Field(default_factory=list)
    'Events to log.'

    # There's a bug here. Ideally, exception would be
    # set to Type[Exception], but it's throwing an odd
    # error asserting that the input value should be
    # of subtype str. Appears to be a bug in Pydantic.
    exception: Any = None
    'Any exception raised during execution.'

    def dict(self, *args, **kwargs):
        out = super().dict(*args, **kwargs)
        out['outcome'] = out['outcome'].value
        return out

class Outputs(BaseModel):
    'List of output objects.'

    __root__: List[Output]
    'Root type for the Outputs object.'

class Breaker(BaseModel, validate_assignment=True):
    '''Breakers behave like circuit breakers: when tripped, they will end
    a brute force attack by throwing a `BreakerTrippedError`. Breakers become
    tripped when an exception class that is included in `exception_classes`
    for the breaker is raised during a brute force attack.
    '''

    exception_classes: List[Type[Exception]]
    'Exception classes the breaker will act on.'

    trip_class: Type[Exception] = BreakerTrippedError
    'Exception classes the Breaker.check will act on.'

    trip_msg: str = 'Breaker tripped'
    'Default message tripped by Breaker.check.'

    def callback(self, e:Exception, log:Logger=None) -> bool:
        '''Callback executed by Breaker.check.

        Args:
          e: Exception instance received by Breaker.check.

        Returns:
          Boolean value determining if check should call
            Breaker.trip.

        Notes:
          - Override this method in subclasses.
          - The default variation of this method will always
            return True.
        '''

        return True

    @check_exceptions('e', 'trip_class')
    def check(self, e:Exception, trip_class:Exception=None,
            trip_msg:str=None, log:Logger=None) -> bool:
        '''Check an exception and determine if the breaker should be
        tripped.

        Args:
          e: Exception to check.
          trip_class: Exception class that will be tripped should
            the breaker be engaged. Otherwise self.trip_class is
            used.
          trip_msg: Message that will be passed to the raised
            exception. Otherwise self.trip_msg is used.
          log: Logger to send log messages.

        Returns:
          Boolean indicating if the exception was handled by the
          breaker.

        Notes:
          - Raises type specified by trip_class or self.trip_class when
            callback returns a non-None value.
          - callback signature: f(e:Exception) -> bool
          - trip signature:
            trip(e:Exception, msg:str, exception_class:Exception)
        '''

        if log: log.module(f'{type(self).__name__} checked: {e}')

        will_handle = isinstance(e, tuple(self.exception_classes))

        if will_handle and self.callback(e, log=log):

            self.trip(
                e = e,
                msg =
                    trip_msg if trip_msg else self.trip_msg,
                exception_class =
                    trip_class if trip_class else self.trip_class
            )

        return will_handle

    @check_exceptions('exception_class')
    def trip(self, msg:str=None, exception_class:Exception=None, *args, **kwargs):
        '''Raise a BreakerTrippedError while using e as the string
        message.

        Args:
            exception_class: Exception class to raise.
        '''

        raise (exception_class if exception_class else self.trip_class)(
            msg if msg else self.default_msg
        )

CALLBACK_ERR = ('Authentication callbacks must return a dict matching '
    f'this schema: Output')

class Callback(BaseModel):
    '''A model representing the authentication callback for a
    BruteLoops attack.'''

    callback: Callable[[str, str], dict]
    'Callback to execute.'

    authentication_jitter: Union[Jitter, None] = None
    'Time to sleep before returning.'

    def __call__(self, username:str, password:str, *args,
            **kwargs) -> Output:
        '''Call the authentication callback.

        Returns:
            An Output instance.
        '''

        output = self.callback(username, password,
            *args, **kwargs)

        # Handle bad return type
        if not isinstance(output, dict):
            raise ValueError(CALLBACK_ERR)

        if not output.get('username', None):
            output['username'] = username
        if not output.get('password', None):
            output['password'] = password

        try:
            # Validate the output
            output = Output(**output)

        except Exception as e:

            # Handle poorly formatted dict
            raise ValueError(CALLBACK_ERR + '({e})')

        finally:

            if self.authentication_jitter:

                # Do authentication jitter
                self.authentication_jitter.sleep()

        return output

class ThresholdBreaker(Breaker, validate_assignment=True):
    '''A breaker that throws only when an event has occurred more
    than "threshold" times.

    Set the `reset_spec` attribute to a string conforming to the
    jitter timing specification to allow the threshold to timeout
    after a given period of time.
    '''

    threshold: int = Field(1, gt=0)
    ('Maximum number of times the breaker can be handled before '
    'throwing an exception.')

    reset_after: str = Field(None, regex=JITTER_RE, alias='reset_spec')
    ('Reset threshold counter after this period of time. Format '
     'follows the same specification as Jitter. Value is converted to '
     'an integer representing the number of seconds upon validation.')

    last_time: datetime.datetime = None
    'The last time that count was incremented.'

    count: int = Field(0, gt=-1)
    'Count of times handle has been called.'

    def __setattr__(self, name:str, value:Any):
        '''Override such that additional checks/modifications are
        performed when the count attribute is incremented.

        Args:
          name: Name of the attribute to set.
          value: Value that is set to the attribute.

        Raises:
          OverflowError: when `self.count` > `self.threshold`

        Notes:
          - Time-based resets are managed here.
        '''

        super().__setattr__(name, value)

        if name == 'count':

            if self.reset_after:

                # Take the current time
                now = BruteTime.current_time(format='datetime')
    
                # Check if we should reset the breaker
                  # - Has to have been checked at least once before
                  # - Value should be greater than 1
                  # - delta between now and last time must be greater than
                  #   self.reset_after
                if self.last_time and (value > 1) and (
                        (now - self.last_time).total_seconds() >=
                        self.reset_after):
    
                    # Enough time has passed to reset the counter
                    self.count = 1
    
                # Set the value of last_time to track the last hit
                self.last_time = now

            if self.count > self.threshold:
                # Raise the overflow exception

                raise OverflowError(
                    f'Breaker threshold broken ({value} > {self.threshold})')

    @validator('reset_after')
    def v_reset(cls, v, field, values):
        'Reset must follow Jitter specification.'

        return jitter_str_to_float(v, field.name)

    @validator('threshold')
    def v_thresh(cls, t):
        'Threshold must be >=1.'

        if t < 1:
            raise ValidationError(
                f'threshold must be greater >=1, got {t}')

        return t

    def callback(self, e:Exception, log:Logger=None) -> bool:
        '''Override the callback method to increment the count
        attribute and handle when the threshold is crossed.

        Returns:
            - True when the threshold has been crossed.
            - False when count < threshold.
        '''

        try:
            self.count += 1
            if log:
                log.module(
                    'Threshold Breaker at: '
                    f'{self.count} of {self.threshold}'
                )
        except OverflowError:
            if log: log.module('Breaker threshold met.')
            return True

        return False

    def reset(self, c:int=0):
        '''Reset the handle count to c.

        Args:
            c: Value to set to handle_count.
        '''

        self.count = c

class Breakers(BaseModel):
    '''A list of breakers to handle exceptions.
    '''

    __root__: List[Union[Breaker,
        ThresholdBreaker]] = Field(default_factory=list)

class Config(BaseModel, extra=Extra.allow):
    '''A model to support configuration of BruteLoops attacks. It provides
    all input validations and conversions such that only a dictionary
    value is required for initialization.'''

    authentication_jitter: Jitter = None
    'Time to sleep between guesses for a given username.'

    max_auth_jitter: Jitter = None
    'Time to sleep after max_auth_tries is hit.'

    process_count: int = 1
    ('Total count of processes to use. Given BL\'s current logic in '
     'control loop, this also indicates the number of parallel '
     'usernames to target in parallel.')

    max_auth_tries: int = None
    ('Maximum number of guesses to make for an account before '
     'engaging max_auth_jitter')

    stop_on_valid: bool = False
    ('Determines if the control loop should halt execution when a valid '
    'credential is recovered.')

    db_file: str
    'Path to the SQLite database file supporting the attack.'

    log_level: LogLevelEnum = 'invalid-username'
    'Level of logging to apply.'

    log_file: str = None
    'File to receive logging events.'

    log_stderr: bool = False
    'Determines if logs should be sent to stderr.'

    log_stdout: bool = True
    'Determines if logs should be sent to stdout.'

    log_format: str = BLogging.LOG_FORMAT
    'Format for log events.'

    randomize_usernames: bool = True
    'Determines if usernames should be randomized.'

    timezone: str = None
    'Timezone for logging.'

    blackout: Blackout = None
    'Setting for when no guessing should occur.'

    exception_handlers: List[ExceptionHandler] = Field(
        default_factory=list)
    'Exception handlers that will receive exceptions.'

    breakers: List[Breaker] = Field(default_factory=list)
    'Breakers to further handle exceptions.'

    authentication_callback: Callable[[str, str], Output]
    'Callback that authenticates credentials.'

    @validator('process_count', 'max_auth_tries')
    def gt_zero(cls, v, field):
        'Enforce minimum values.'

        if not isinstance(v, int):
            raise ValueError(f'{field.name} must be an integer.')
        elif v < 1:
            raise ValueError(f'{field.name} must be >0, got {v}')

        return v

    @validator('authentication_callback')
    def v_auth_callback(cls, v, values):
        'Configure the attack\'s authentication callback.'

        return Callback(
            callback=v,
            authentication_jitter=values.get(
                'authentication_jitter',
                None))

    @validator('timezone')
    def v_timezone(cls, tz):
        'Set and return the BruteTime timezone.'

        if tz is not None:
            BruteTime.set_timezone(tz)

        return tz

    @validator('log_level')
    def v_log_level(cls, v):
        'Derive the proper logging level from name.'

        return getattr(BLogging, v.name)

    def __init__(self, *args, **kwargs):

        # ====================
        # REMOVE EMPTY JITTERS
        # ====================

        for k in ('authentication_jitter', 'max_auth_jitter',):
            jitter = kwargs.get(k)

            if not jitter:
                if k in kwargs:
                    del(kwargs[k])
                continue

            min, max = jitter.get('min', ''), jitter.get('max','')

            if (not min and not max) or \
                    (EJP.match(min) and EJP.match(max)):
                del(kwargs[k])
                continue

        # =====================
        # FINISH INITIALIZATION
        # =====================

        super().__init__(*args, **kwargs)

        # Session maker
        self.session_maker = Session(self.db_file)
