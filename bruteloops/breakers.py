from .errors import BreakerThrownError
from logging import Logger
from functools import wraps
from typing import List, Type
import inspect

def is_exception(t) -> bool:
    '''Ensure t is an subtype of Exception.

    Returns:
        True when t is a subtype of Exception.

    Raises:
        TypeError when t is not a subtype of Exception.
    '''

    if not isinstance(t, E_BASES):
        raise TypeError(
            f'{type(t)} is not a subtype of Exception')

    return True

def check_exceptions(*kwargs:List[str]):
    '''Ensure that each kwarg maps to one or more Exception
    instances.
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

                if isinstance(bound.arguments[k], list):
                    for e in bound.arguments[k]:
                        is_exception(e)
                else:
                    is_exception(bound.arguments[k])

            # Executed the decorated function
            return f(*args, **kwargs)

        return inner

    return outer

class Breaker:
    '''Breakers provide a method of handling exceptions that are
    raised during execution of the main control loop.

    Breakers accept a list of exception classes to be compared
    against when an exception instance is passed to the check
    method. The main control loop catches exceptions and passes
    them to breakers.
    '''

    @check_exceptions('exception_classes', 'throw_class')
    def __init__(self, exception_classes: List[Type[Exception]],
            throw_class:Type[Exception]=BreakerThrownError,
            throw_msg:str='Breaker thrown'):
        '''
        '''

        self.exception_classes = exception_classes
        'Exception classes the Breaker.check will act on.'

        self.throw_class = throw_class
        'Default exception class raised by Breaker.check.'

        self.throw_msg = throw_msg
        'Default message thrown by Breaker.check.'

    def callback(self, e:Exception) -> bool:
        '''Callback executed by Breaker.check.

        Args:
            e: Exception instance received by Breaker.check.

        Returns:
            Boolean value determining if check should call
              Breaker.throw.

        Notes:
            - Override this method in subclasses.
            - The default variation of this method will always
              return True.
        '''

        return True

    @check_exceptions('e', 'throw_class')
    def check(self, e:Exception, throw_class:Exception=None,
            throw_msg=None, log:Logger=None) -> False:
        '''Check an exception and determine if the breaker should be
        thrown.

        Args:
            e: Exception to check.
            throw_class: Exception class that will be thrown should
              the breaker be engaged. Otherwise self.throw_class is
              used.
            throw_msg: Message that will be passed to the raised
              exception. Otherwise self.throw_msg is used.
            log: Logger to send log messages.

        Raises:
            - Type specified by throw_class or self.throw_class when
              callback returns a non-None value.

        Notes:
            - callback signature: f(e:Exception) -> bool
            - throw signature:
              throw(e:Exception, msg:str, eclass:Exception)
        '''

        if log is not None:

            log.info(f'{type(self.__name__)} checked: {e}')

        if isinstance(e, self.exception_classes) and \
                self.callback(e):

            self.throw(
                e = e,
                msg =
                    throw_msg if throw_msg else self.throw_msg,
                eclass =
                    throw_class if throw_class else self.throw_class
            )

        return False

    @check_exceptions('eclass')
    def throw(self, msg:str=None, eclass:Exception=None, *args, **kwargs):
        '''Raise a BreakerThrownError while using e as the string
        message.

        Args:
            eclass: Exception class to raise.
        '''

        raise (eclass if eclass else self.throw_class)(
            msg = msg if msg else self.default_msg
        )

class ThresholdBreaker(Breaker):

    def __init__(self, threshold:int, count:int, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self.t = threshold
        ('Indicates the maximum number of times a breaker '
        'condition may occur before a BreakerThrownError '
        'is raised.')

        self.c = count
        ('Indicates the number of times a breaker condition '
        'has occurred.')

    @property
    def threshold(self) -> int:
        'Return the current threshold.'

        return self.t

    @threshold.setter
    def threshold(self, t:int) -> None:
        '''Set the threshold.

        Args:
            t: Threshold value.

        Raises:
            - ValueError when t < self.count
            - TypeError when type(t) != int
        '''

        if not isinstance(t, int):
            raise TypeError('threshold must be an integer')
        elif t < count:
            raise ValueError(
                f'threshold must be >= self.count')
        elif t < 1:
            raise ValueError(
                f'threshold must be >= 1')

        self.t = t

    @property
    def count(self) -> int:
        'Get the current count.'

        return self.c

    @count.setter
    def count(self, c:int) -> None:
        '''Set the count value.

        This indicates the number of times breaker conditions
        have occurred.

        Args:
            c: current count.

        Raises:
            - TypeError when type(c) != int
            - BreakerThrownError when c > self.threshold
        '''

        if not isinstance(c, int):
            raise TypeError('count must be an integer')
        elif c > count:
            raise OverflowError('count > threshold')

        self.c = c

    def callback(self, e:Exception, log:Logger=None) -> bool:
        '''Override the callback method to increment the count
        attribute and handle when the threshold is crossed.

        Returns:
            - True when the threshold has been crossed.
            - False when count < threshold.
        '''

        try:
            self.count += 1
        except OverflowError:
            return True

        return False

    def reset(self, c:int=0):
        '''Reset the handle count to c.

        Args:
            c: Value to set to handle_count.
        '''

        self.count = c
