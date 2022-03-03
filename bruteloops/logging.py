#!/usr/bin/env python3
from sys import stdout,stderr
import logging
from functools import wraps
from datetime import datetime, timezone as TZ
from zoneinfo import ZoneInfo
from .errors import TimezoneError, LoggingError

# ================
# GENERAL DEFAULTS
# ================

LOG_FORMAT='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_TZ = datetime.now(TZ.utc) \
    .astimezone() \
    .tzname()

# =====================
# DEFINE LOGGING LEVELS
# =====================

GENERAL_EVENTS      = 90
CREDENTIAL_EVENTS   = 85
VALID_CREDENTIALS   = 80
SLEEP_EVENTS        = 70
INVALID_USERNAME    = 60

logging.addLevelName(INVALID_USERNAME, 'INVALID_USERNAME')
logging.addLevelName(SLEEP_EVENTS,'SLEEP_EVENT')
logging.addLevelName(VALID_CREDENTIALS,'VALID')
logging.addLevelName(CREDENTIAL_EVENTS,'INVALID')
logging.addLevelName(GENERAL_EVENTS,'GENERAL')

# =========================
# LEVEL LOOKUP DICTIONARIES
# =========================

LEVEL_LOOKUP = dict(general=GENERAL_EVENTS,
    valid=VALID_CREDENTIALS,
    invalid=CREDENTIAL_EVENTS,
    invalid_username=INVALID_USERNAME)

SYNONYM_LOOKUP = dict(
    general=('general','general-events','general-event',),
    valid=('valid','valid-credentials','valid-credential',),
    invalid=('invalid','invalid-credentials','invalid-credential',),
    invalid_username=('invalid-usernames','invalid-username',))

def lookup_log_level(level:str) -> int:
    '''Derive logging level from string name.

    Args:
        level: Name of the level to reveal.

    Returns:
        `int` logging level.

    Raises:
        bruteloops.errors.LoggingError when an invalid logginlevel
          is provided.
    '''

    for level_key, synonyms in SYNONYM_LOOKUP.items():

        if level in synonyms:
            break
        level_key = None

    if not level_key:

        raise LoggingError.invalidLevelName(
            f'Invalid log level supplied: {level}')

    return LEVEL_LOOKUP[level_key]
            
def init_handler(logger, klass, formatter, *args, **kwargs):

    handler = klass(*args, **kwargs)
    handler.setFormatter(formatter(LOG_FORMAT))
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

    @do_log(INVALID_USERNAME)
    def invalid_username(self, m:str):
        '''Log invalid username events.

        Args:
            m: The string message to log.
        '''

        pass

    @do_log(CREDENTIAL_EVENTS)
    def credential(self, m:str):
        '''Log credential events.

        Args:
            m: The string message to log.
        '''

        pass

    @do_log(GENERAL_EVENTS)
    def module(self, m:str):
        '''Log module events.

        Args:
            m: The string message to log.
        '''

        pass

    @do_log(GENERAL_EVENTS)
    def general(self, m:str):
        '''Log general events.

        Args:
            m: The string message to log.
        '''

        pass

if logging.getLoggerClass() != BruteLogger:
    logging.setLoggerClass(BruteLogger)

def formatterFactory(timezone:str=None):

    # Update the TIMEZONE class property to a ZoneInfo
    try:
        if timezone == None:
            timezone = ZoneInfo(DEFAULT_TZ)
        else:
            timezone = ZoneInfo(timezone)
    except Exception as e:
        raise(TimezoneError.invalidTZ(timezone, extra=e))

    class Formatter(logging.Formatter):

        @property
        def timezone(self):
            return timezone
    
        def converter(self, timestamp):
            out = datetime.fromtimestamp(
                timestamp,
                self.timezone).timetuple()
            return out

    return Formatter

DEFAULT_FORMATTER = formatterFactory()
            
def getLogger(name, log_level='invalid',
        log_file=None, log_stdout=False, log_stderr=True,
        timezone=None, formatter=DEFAULT_FORMATTER):
    '''Configure a logger for the library.
    '''

    logger = logging.getLogger(name)
    logger.propagate = False

    if timezone is not None and formatter == DEFAULT_FORMATTER:

        # ==============================
        # OVERRIDE WITH CUSTOM FORMATTER
        # ==============================

        formatter = formatterFactory(timezone)

    # ==================
    # CONFIGURE HANDLERS
    # ==================

    if log_file:

        init_handler(logger,
            logging.FileHandler,
            formatter,
            log_file)

    if log_stdout:

        init_handler(logger,
            logging.StreamHandler,
            formatter,
            stdout)

    if log_stderr:

        init_handler(logger,
            logging.StreamHandler,
            formatter,
            stderr)

    # =================
    # SET LOGGING LEVEL
    # =================

    if isinstance(log_level, str):
        logger.setLevel(
            lookup_log_level(log_level))
    else:
        logger.setLevel(log_level)

    return logger
