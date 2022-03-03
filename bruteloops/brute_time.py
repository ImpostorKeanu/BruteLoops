import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from .errors import TimezoneError

class BruteTime:

    # default template for time format
    # see documentation for time.strftime for more information on formatting
    str_format = '%H:%M:%S %Z (%y/%m/%d)'

    # Get the default timezone.
    timezone = ZoneInfo(
        datetime.now(timezone.utc).astimezone().tzname())

    @staticmethod
    def set_timezone(key):
        '''Set the timezone for timestamps.

        Args:
            key: Either a `str` that point to the name of the target
              timezone or a `zoneinfo.ZoneInfo` instance representing
              the timezone itself.
        '''

        if isinstance(key, str):        
            try:
                BruteTime.timezone = ZoneInfo(key)
            except Exception as e:
                raise TimezoneError.invalidTZ(key)
        elif isinstance(key, ZoneInfo):
            BruteTime.timezone = key
        else:
            raise ValueError(
                'Timezone configuration must be a string or ZoneInfo.')

    @staticmethod
    def future_time(seconds:float, format:object=float,
            str_format:str=str_format):
        '''Calculate the future time from current time.

        Args:
            seconds: Number of seconds into the future.
            format: Value indicating the desired format. Supported
              values: `str`, "struct_time".
            str_format: Format string when `str` is supplied
              to format.

        Returns:
            - When `str` is supplied to `format`, a formatted string
              is returned.
            - When "struct_time" is supplied, a `datetime.time.timetuple`
              instance is returned.
            - Otherwise, a `float` is returned.
        '''

        future = BruteTime.current_time()+seconds

        if format == str:
            return BruteTime.float_to_str(future, str_format)
        elif format == 'struct_time':
            return datetime \
                    .fromtimestamp(future, BruteTime.timezone) \
                    .timetuple()
        else:
            return future

    @staticmethod
    def current_time(format:object=float, str_format:str=str_format):
        '''Return the current time in the specified format.

        Args:
            format: Specifies the return format. Supply `str` to
              return a formatted string.
            str_format: The format string to use.

        Returns:
            - When `str` is supplied to `format`, a formatted string
              is returned.
            - When `float` is supplied to `format`, a float is returned.
            - when `datetime`, a `datetime` object is returned.
        '''

        dt = datetime.now(BruteTime.timezone)
        if format == str:
            return dt.strftime(str_format)
        if format in (datetime, 'datetime',):
            return dt
        else:
            return dt.timestamp()

    @staticmethod
    def float_to_str(float_time:float, str_format:str=str_format) -> str:
        '''Return the float time, as returned by time.time(),
        as a formatted string.

        Args:
            float_time: Float value to convert to string.
            str_format: Format string.

        Returns:
            Formatted `str`.
        '''

        return datetime \
            .fromtimestamp(float_time, BruteTime.timezone) \
            .strftime(str_format)
