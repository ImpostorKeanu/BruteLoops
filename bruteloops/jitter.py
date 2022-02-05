import re
import time
from .brute_time import BruteTime
from random import uniform

class JitterTime(BruteTime):
    ''''
    Class that provides functions capable of validating and converting time as
    required for the library.
    '''

    s = seconds = 1
    m = minutes = s*60
    h = hours   = m*60
    d = days    = h*24

    time_re = re.compile('^(?P<value>'\
        '(?P<float>[0-9]?\.[0-9]+)|(?P<decimal>[1-9][0-9]*))'\
        '(?P<unit>s|m|h|d){1}$')

    @staticmethod
    def conv_time_match(groups):
        '''
        Convert the time to an integer value.
        '''

        return (
            float(groups['value']) * JitterTime.__dict__[groups['unit']]
        )

    @staticmethod
    def validate_time(time):
        '''
        Validate a string to assure it matches the appropriate jitter format.
        '''

        m = re.match(JitterTime.time_re,time)
        if m:
            return m
        else:
            return False


class Jitter:
    '''
    Jitter objects represent a configuration from which a range of time will be
    interpreted, which are is as input to ```time.sleep``` when instructing brute
    force logic to sleep for a determined period of time. This can be used to prevent
    overwhelming network services with too many authentication calls or locking
    of user accounts.
    '''

    def __init__(self,min,max):
        '''
        Initialize a Jitter object. ```min``` indicates the minimum length of 
        time to sleep and ```max``` indicates the maximum length of time to
        sleep. Set ```alert``` to ```True``` should the default alerts printed
        to stdout be desired.

        # Arguments

        - ```min``` - the minimum length of time to sleep (see Min/Max Format for format
        specification)
        - ```max``` - the mximum length of time to sleep (see Min/Max Format for format
        specification)

        # Min/Max Format

        ```min``` and ```max``` arguments are expected to be a floating point
        value that used as multipliers and a single letter suffix used to indicate
        the desired unit of time. The multiplier will be applied to the unit.
        Thus, two hours can be represented as ```2h``` and five minutes can
        be represented as ```5m```.

        ## Supported Time Units

        - ```s``` - seconds
        - ```m``` - minutes
        - ```h``` - hours
        - ```d``` - days

        ## Examples

        - ```10m``` - 10 minute interval
        ` ```2h``` - 2 hour interval
        '''
       
        # VALIDATE INPUTS
        min_match = JitterTime.validate_time(min)
        assert min_match, (
            'Jitter minimum is an invalid format'
        )

        max_match = JitterTime.validate_time(max)
        assert max_match, (
            'Jitter max is an invalid format'
        )

        # Setting instance variables
        self.orig_min = min
        self.orig_max = max
        self.min = JitterTime.conv_time_match(min_match.groupdict())
        self.max = JitterTime.conv_time_match(max_match.groupdict())

        # Assert that the minimum is less than the maximum
        assert self.min <= self.max, (
            f'Jitter minimum must be less or equal to maximum ({self.min} <= {self.max})'
        )

    def __str__(self):

        return f'<Jitter(min="{self.orig_min}", max="{self.orig_max}")>'

    def sleep(self):
        '''
        Make the current process sleep for a given period of time based on
        the values set for ```self.min``` and ```self.max```.
        '''

        stime = self.get_jitter_duration()

        time.sleep(
            (stime)
        )

    def get_jitter_duration(self):
        '''
        Return a floating point number in the range specified for jitter time.
        '''

        return uniform(self.min, self.max)

    def get_jitter_future(self,current_time=None):
        
        current_time = current_time or BruteTime.current_time()

        return current_time + self.get_jitter_duration()

