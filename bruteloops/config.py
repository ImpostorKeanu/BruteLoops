#!/usr/bin/env python3

from .jitter import Jitter
from . import sql
from .callback import Callback
from . import logging as BL
from pathlib import Path
from sys import stdout,stderr
from .db_manager import Session
import inspect
import logging

class Config:
    '''
    Configuration object that is consumed by BruteForce objects. Configurations
    specified here dictate various aspects of the brute force attack, as well
    as logging and exception handling.

    # Attack Configuration Parameters

    - `process_count` - `integer` value - The number of child processes to spawn to support
        the attack. Each process will be used to make distinct calls to the
        authentication_callback.
    ` `authentication_callback` - `function`, `callable` - A function or objection
        implementing `__call__` that is expected to received two arguments: `username`
        and `password`. The callback should return a three-item tuple in the form of:
        `(outcome, username, password)`, where `outcome` should be an integer value
        that determines if authentication was successful -- `0` for unsuccessful and
        `1` for successful.
    - `authentication_jitter`- `Jitter` object - A `Jitter'
        object that determines how long a child process should sleep after running the
        `authentication_callback`. See the jitter documentation for information on
        proper formatting.
    - `max_auth_jitter` - `Jitter` object - A `Jitter` object that
        determines how long a period of time should pass before attempting further
        authentication attempts. Follows the same format as `Jitter`.
    - `max_auth_tries` - Number of simultaneous authentication attempts to perform for
        a given user before sleeping for a period of time indicated by `Jitter`.
        Should a standard horizontal brute force attack be desired, set this value to `1`.

    # Logging Configuration Parameters

    These configurations are optional.

    ## Log Destinations

    The following parameters can be used to configure where log records are sent. These values
    are not mutually exclusive, i.e. it is possible to log to a `log_file` and `log_stdout`
    simultaneously.

    - `log_file` - `string` value -  Log records to a file named at this parameter. Records are
        appended to the log file.
    - `log_stdout' - `boolean` value - Log events to `stdout`. 
    - `log_stderr` - `boolean` value - Log events to `stderr`.

    ## Logging Level Specification

    - `log_valid` - `boolean` value - Log valid records to each destination.
    - `log_invalid` - `boolean` value - Log all authentication records, i.e. both valid and invalid.
    - `log_general` - `boolean` value - Log all relevant events to each destination.
    '''

    def __init__(self,
            process_count=1,                # NUMBER OF CHILD PROCESSES TO RUN
            authentication_callback=None,   # AUTHENTICATION CALLBACK
            authentication_jitter=None,     # JITTER AFTER EACH AUTHENTICATION ATTEMPT
            max_auth_jitter=None,           # JITTER AFTER EACH PASSWORD ITERATION
            max_auth_tries=1,               # JITTER ONLY AFTER A THRESHOLD
            stop_on_valid=False,            # STOP AFTER A SINGLE CREDENTIAL IS RECOVERED
            db_file=None,                   # SQLITE DATABASE FILE
            log_valid=False,                # ALERT TO STDOUT ON VALID CREDENTIALS
            log_invalid=False,              # ALERT TO STDOUT ON INVALID CREDENTIALS
            log_general=False,              # GENERAL BRUTEFORCE ALERTS
            log_file=False,                 # FILE TO RECEIVE ADDITIONAL LOGS
            log_stdout=False,               # LOG EVENTS TO STDOUT
            log_stderr=False,               # LOG EVENTS TO STDERR
            exception_handlers=None):        # DICTIONARY OF EXCEPTION HANDLERS: {class:exception_handler}

        self.process_count              = process_count
        self.authentication_callback    = authentication_callback
        self.authentication_jitter      = authentication_jitter
        self.max_auth_jitter            = max_auth_jitter
        self.max_auth_tries             = max_auth_tries
        self.stop_on_valid              = stop_on_valid
        self.db_file                    = db_file
        self.log_valid                  = log_valid
        self.log_invalid                = log_invalid
        self.log_general                = log_general
        self.log_file                   = log_file
        self.log_stdout                 = log_stdout
        self.log_stderr                 = log_stderr
        self.exception_handlers         = exception_handlers if \
                exception_handlers else {}
        self.log_level                  = 90
        self.validated                  = False

    def validate(self):

        # ==========================
        # ASSERT REQUIRED PARAMETERS
        # ==========================
        assert self.process_count, 'A Config object requires a process_count'
        assert self.process_count.__class__ == int, (
            'Process count must be an integer value'
        )
        assert self.db_file, 'A path to a SQLite database is required. '\
            'Library will create one should the file itself not yet exist.'
        assert self.authentication_callback, (
            'A callback must be set on the Config object'
        )

        if self.exception_handlers:

            assert type(self.exception_handlers) == dict, (
                'exception_handlers is intended to be a dictionary, where\n'\
                'each key is an exception class and the value a function\n'\
                'which the exception will execute. The current brute object\n'\
                'will be passed to the function as an argument.\n'\
                f'Current type: {type(self.exception_handlers)}'
            )

        # ===============================
        # SET THE AUTHENTICATION_CALLBACK
        # ===============================
        self.authentication_callback = Callback(
            self.authentication_callback,
            self.authentication_jitter
        )

        # =====================
        # SQLITE INITIALIZATION
        # =====================
        self.session_maker = Session(self.db_file)

        # UPDATE THE OBJECT TO REFLECT VALIDATED STATE
        self.validated = True
