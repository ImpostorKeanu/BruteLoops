import time

class BruteTime:

    # default template for time format
    # see documentation for time.strftime for more information on formatting
    str_format = '%H:%M:%S %Z (%y/%m/%d)'

    @staticmethod
    def future_time(seconds,format=int,str_format=str_format):
        '''
        Calculate the future time from current time.
        '''

        future = BruteTime.current_time()+seconds

        if format == str:
            return time.strftime(
                str_format, time.localtime(future)
            )
        elif format == 'struct_time':
            return time.localtime(future)
        else:
            return future

    @staticmethod
    def current_time(format=int,str_format=str_format):
        '''
        Return the current time.
        '''

        if format == str:
            return time.strftime(str_format)
        else:
            return time.time()

    @staticmethod
    def float_to_str(float_time,str_format=str_format):
        '''
        Return the float time, as returned by time.time(), as a formatted string.
        '''

        return time.strftime(str_format,time.localtime(float_time))
