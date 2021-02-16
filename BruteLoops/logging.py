#!/usr/bin/env python3
from sys import stdout,stderr
import logging

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
