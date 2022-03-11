#!/usr/bin/env python3

from .jitter import Jitter
from . import sql
from .callback import Callback
from . import logging as BL
from .brute_time import BruteTime
from pathlib import Path
from sys import stdout,stderr
from .db_manager import Session
from time import struct_time
from dataclasses import dataclass
import datetime
import inspect
import logging

@dataclass
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

    process_count:int               = 1
    authentication_callback:object  = None
    authentication_jitter:str       = None
    max_auth_jitter:str             = None
    max_auth_tries:int              = 1
    stop_on_valid:bool              = False
    db_file:str                     = None
    log_level:int                   = False
    log_file:str                    = False
    log_stdout:bool                 = False
    log_stderr:bool                 = False
    randomize_usernames:bool        = True
    timezone:str                    = None
    blackout_start:struct_time      = None
    blackout_stop:struct_time       = None
    validated:bool                  = False
    exception_handlers:dict         = None

    def validate(self):
        '''Validate configuration values.
        '''

        # Process count
        if not (isinstance(self.process_count, int) and
                self.process_count >= 1):

            raise ValueError(
                'Config objects require a process_count integer.')

        # Database file
        if not isinstance(self.db_file, str):

            raise ValueError(
                'A path to a SQLite database is required. Library will '
                'create one should the file itself not yet exist.')

        # Authentication callback
        if self.authentication_callback is None or not \
                hasattr(self.authentication_callback, '__call__'):
            raise ValueError(
                'A callback must be set on the Config object')

        # Exception handlers
        if self.exception_handlers and not \
                isinstance(self.exception_handlers, dict):

            raise ValueError(
                'exception_handlers is intended to be a dictionary, '
                'where each key is an exception class and the value '
                'a function which the exception will execute. The '
                'current brute object will be passed to the function '
                'as an argument. '
                f'Current type: {type(self.exception_handlers)}')

        elif self.exception_handlers is None:

            self.exception_handlers = {}

        # Blackout_start/stop
        if self.blackout_start and not self.blackout_stop:

            raise ValueError(
                'Blackout values must be supplied as a start/stop '
                'pair.')

        # Log level
        if self.log_level is None:
            self.log_level = 90

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

        if self.timezone != None:
            BruteTime.set_timezone(self.timezone)

        # =====================
        # HANDLE BLACKOUT RANGE
        # =====================

        if (self.blackout_start or self.blackout_stop) and not (
                self.blackout_start and self.blackout_stop):

            raise ValueError(
                'blackout_start must always be paired with a '
                'blackout_stop')

        elif self.blackout_start and self.blackout_stop:

            if not isinstance(self.blackout_start, struct_time) or not \
                    isinstance(self.blackout_stop, struct_time):
                
                raise ValueError(
                    'blackout_start and blackout_stop values must '
                    'be of type "time.struct_time".'
                )

                # ==================================================
                # CONVERT BLACKOUT VALUES TO datetime.time INSTANCES
                # ==================================================

                self.blackout_start = datetime.time(
                    hour=blackout_start.tm_hour,
                    minute=blackout_start.tm_min,
                    second=blackout_start.tm_sec)

                self.blackout_stop = datetime.time(
                    hour=blackout_stop.tm_hour,
                    minute=blackout_stop.tm_min,
                    second=blackout_stop.tm_sec)
