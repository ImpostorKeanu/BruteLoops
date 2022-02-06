#!/usr/bin/env python3
from sys import stdout,stderr
import logging
from functools import wraps

SLEEP_EVENTS            = 85
VALID_CREDENTIALS       = 80
CREDENTIAL_EVENTS       = 70
GENERAL_EVENTS          = 60

FORMAT='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FORMAT = logging.Formatter(FORMAT)

logging.addLevelName(SLEEP_EVENTS,'SLEEP_EVENT')
logging.addLevelName(VALID_CREDENTIALS,'VALID')
logging.addLevelName(CREDENTIAL_EVENTS,'INVALID')
logging.addLevelName(GENERAL_EVENTS,'GENERAL')

def init_handler(logger, klass, *args, **kwargs):

    handler = klass(*args, **kwargs)
    handler.setFormatter(LOG_FORMAT)
    logger.addHandler(handler)

def do_log(level):
    '''Decorator to simplify custom logging levels.

    Args:
        level: The custom level to pass to the decorated
            logging method.
    '''

    def decorator(f):

        @wraps(f)
        def wrapper(logger, m:str):

            # Log with the proper level
            logger.log(level, m)

        return wrapper

    return decorator

class BruteLogger(logging.Logger):

    @do_log(SLEEP_EVENTS)
    def sleep(self, m:str):
        '''Log sleep events.

        Args:
            m: The string message to log.
        '''

        pass

    @do_log(VALID_CREDENTIALS)
    def valid(self, m:str):
        '''Log valid credential events.

        Args:
            m: The string message to log.
        '''

        pass

    @do_log(CREDENTIAL_EVENTS)
    def invalid(self, m:str):
        '''Log invalid credential events.

        Args:
            m: The string message to log.
        '''

        pass

    @do_log(CREDENTIAL_EVENTS)
    def credential(self, m:str):

        pass

    @do_log(GENERAL_EVENTS)
    def general(self, m:str):
        '''Log general events.

        Args:
            m: The string message to log.
        '''

        pass

logging.setLoggerClass(BruteLogger)

def getLogger(name, log_level=GENERAL_EVENTS, log_valid=False,
        log_invalid=False, log_general=False, log_file=None,
        log_stdout=False, log_stderr=True):
    'Configure a logger for the library'

    logger = logging.getLogger(name)
    
    if log_valid or log_invalid or log_general:
        
        if log_valid:   log_level = VALID_CREDENTIALS
        if log_invalid: log_level = CREDENTIAL_EVENTS
        if log_general: log_level = GENERAL_EVENTS

    if log_file:

        init_handler(logger,
            logging.FileHandler,
            log_file)

    if log_stdout:

        init_handler(logger,
            logging.StreamHandler,
            stdout)

    if log_stderr:

        init_handler(logger,
            logging.StreamHandler,
            stderr)

    logger.setLevel(log_level)

    return logger
