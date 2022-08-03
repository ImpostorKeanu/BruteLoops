import re
import time
from .brute_time import BruteTime
from random import uniform

JITTER_RE = '^(?P<value>'\
    '(?P<float>[0-9]?\\.[0-9]+)|(?P<decimal>[1-9][0-9]*))'\
    '(?P<unit>s|m|h|d){1}$'

class JitterTime(BruteTime):
    ''''
    Class that provides functions capable of validating and converting time as
    required for the library.
    '''

    s = seconds = 1
    m = minutes = s*60
    h = hours   = m*60
    d = days    = h*24

    time_re = re.compile(JITTER_RE)

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
