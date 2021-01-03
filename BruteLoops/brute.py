#!/usr/bin/env python3

#from .logging import *
from BruteLoops.logging import *
from . import logging
from .brute_time import BruteTime
from . import sql
from .config import Config
from .db_manager import *
from sqlalchemy.orm.session import close_all_sessions
from pathlib import Path
from uuid import uuid4
from collections import namedtuple
from copy import deepcopy
from time import sleep,time
from types import FunctionType, MethodType
import traceback
import re
import signal
import logging
from time import time

UNKNOWN_PRIORITIZED_USERNAME_MSG = \
    'Prioritized username value supplied ' \
    'during configuration that does not a' \
    'ppear in the database. Insert this v' \
    'alue or remove it from the configura' \
    'tion: {username}'

UNKNOWN_PRIORITIZED_PASSWORD_MSG = \
    'Prioritized password value supplied ' \
    'during configuration that does not a' \
    'ppear in the database. Insert this v' \
    'alue or remove it from the configura' \
    'tion: {password}'

logger = None

class BruteForcer:
    '''Base object from which all other brute forcers will inherit.
    Provides all basic functionality, less brute force logic.
    '''

    def __init__(self, config, use_billiard=False):
        '''Initialize the BruteForcer object, including processes.

        - config - A BruteLoops.config.Config object providing all
        configuration parameters to proceed with the attack.
        '''

        if not config.validated: config.validate()

        # DB SESSION FOR MAIN PROCESS
        self.main_db_sess = config.session_maker.new()
        self.handler_db_sess = config.session_maker.new()

        # ==============================
        # BASIC CONFIGURATION PARAMETERS
        # ==============================

        self.config   = config
        self.presults = []
        self.pool     = None
        self.attack   = None
        self.logger   = getLogger('BruteLoops.BruteForcer',
            config.log_level, config.log_valid, config.log_invalid,
            config.log_general, config.log_file, config.log_stdout,
            config.log_stderr)
        
        self.logger.log(
            GENERAL_EVENTS,
            f'Initializing {config.process_count} process(es)'
        )
        
        # ===================================
        # LOG ATTACK CONFIGURATION PARAMETERS
        # ===================================

        self.logger.log(GENERAL_EVENTS,
                'Logging attack configuration parameters')

        config_attrs = [
                'authentication_jitter',
                'max_auth_jitter',
                'max_auth_tries',
                'stop_on_valid',
                'db_file',
                'log_file',
                'log_valid',
                'log_invalid',
                'log_general',
                'log_stdout',
                'log_stderr'
        ]

        for attr in config_attrs:
            self.logger.log(GENERAL_EVENTS,
                    f'Config Parameter -- {attr}: '+str(getattr(self.config,attr)))

        if hasattr(self.config.authentication_callback, 'callback_name'):
            self.logger.log(GENERAL_EVENTS,
                    f'Config Parameter -- callback_name: '+ \
                            getattr(self.config.authentication_callback,
                                'callback_name'))
            
        # =============================================================
        # REASSIGN DEFAULT SIGNAL HANDLER AND INITIALIZE A PROCESS POOL
        # =============================================================

        original_sigint_handler = signal.signal(signal.SIGINT,signal.SIG_IGN)

        if use_billiard:

            import billiard
            self.pool = billiard.Pool(processes=config.process_count)

        else:

            from multiprocessing.pool import Pool

            self.pool = Pool(processes=config.process_count)

        if not KeyboardInterrupt in self.config.exception_handlers:

            def handler(sig,exception):
                print('SIGINT Captured -- Shutting down ' \
                      'attack\n')
                self.shutdown()
                print('Exiting')
                exit(sig)

            self.config.exception_handlers[KeyboardInterrupt] = handler

        if KeyboardInterrupt in self.config.exception_handlers:

            sigint_handler = config.exception_handlers[KeyboardInterrupt]

            sigint_class = sigint_handler.__class__

            if sigint_class != MethodType and sigint_class != FunctionType:

                assert '__call__' in sigint_handler.__dict__, (
                    'Exception handler must implement __call__'
                )

                call_class = sigint_handler.__getattribute__('__call__').__class__

                assert call_class == FunctionType or call_class == MethodType, (
                    '__call__ must be of type FunctionType or MethodType'
                )

            signal.signal(signal.SIGINT, sigint_handler)


        else: signal.signal(signal.SIGINT, original_sigint_handler)

        # =================
        # HANDLE THE ATTACK
        # =================
        
        current_time = BruteTime.current_time(format=str)
        self.logger.log(GENERAL_EVENTS,
                f'Beginning attack: {current_time}')

        # CREATE A NEW ATTACK
        self.attack = sql.Attack(start_time=BruteTime.current_time())
        self.main_db_sess.add(self.attack)
        self.main_db_sess.commit()

        self.config = config

        # Realign future jitter times with the current configuration
        self.realign_future_time()

    def handle_outputs(self, outputs):
        '''Handle outputs from the authentication callback. It expects a list of
        tuples/lists conforming to the following format:

        ```
            output_list = [
               (<OUTCOME>,<USERNAME>,<PASSWORD>),
               (<OUTCOME>,<USERNAME>,<PASSWORD>)
            ]

        ```

        In the structure below:

        - `OUTCOME` - is an integer value indicating if authentication was
        successful (1 for true, 0 for false)
        - `USERNAME` - string value of the username
        - `PASSWORD` - string value of the password
        '''

        # ==================================================
        # DETERMINE AND HANDLE VALID_CREDENTIALS CREDENTIALS
        # ==================================================

        recovered = False
        for output in outputs:

            # ===============================
            # QUERY FOR THE TARGET CREDENTIAL
            # ===============================

            credential = self.handler_db_sess \
                    .query(sql.Credential) \
                    .join(sql.Username) \
                    .join(sql.Password) \
                    .filter(
                        sql.Username.value == output[1],
                        sql.Password.value == output[2],
                        sql.Username.recovered == False) \
                    .first()

            if not credential: continue

            credential.guessed=True

            # ======================
            # HANDLE THE CREDENTIALS
            # ======================

            cred = f'{output[1]}:{output[2]}'

            # Handle valid credentials
            if output[0]:

                recovered = True
                self.logger.log(VALID_CREDENTIALS,cred)

                # Update username to "recovered"
                credential.username.recovered=True

                # Update the credential to valid
                credential.valid=True

            # Credentials are no good
            else: 

                # Update the credential to invalid
                credential.valid=False
                self.logger.log(CREDENTIAL_EVENTS,cred)


        # Commit the changes
        self.handler_db_sess.commit()

        return recovered

    def realign_future_time(self):
        '''Iterate over each imported username value and rejitter
        the future time based on the current max_authentication_jitter
        '''
        
        # Get all relevant username values
        usernames = self.main_db_sess.query(sql.Username) \
                .filter(
                    sql.Username.recovered == False,
                    sql.Username.last_time > -1.0,
                )

        # Iterate over each username
        for username in usernames:

            # If there's a max_auth_jitter configuration
            if self.config.max_auth_jitter:

                # Generate a new jitter value
                username.future_time = \
                    self.config.max_auth_jitter.get_jitter_future(
                                current_time=username.last_time
                            )

            # Otherwise, set it to the default value of -1.0
            else: username.future_time = -1.0

        # Commit the changes to the database
        self.main_db_sess.commit()

    def monitor_processes(self,ready_all=False):
        '''Iterate over each process in ```self.presults``` and wait
        for a process to complete execution. ```ready_all```
        indciates that monitoring will continue looping until all
        processes complete execution, otherwise a list of outputs
        will be returned after a single process is finished.

        Returns a list of output objects from the
        ```self.authentication_callback``` function and the first
        three elements should follow the pattern below:

        ```
        output = [
            0,        # indicator of successful authentication; 0=failure, 1=success
            username, # string representing the username used during authentication
            password  # string representing the password used during authentication
        ]
        ```
        '''
       
        outputs = []
        while True:

            # iterate over each result
            for result in self.presults:
                
                # act on results that are ready
                if result.ready():

                    # append outputs from the result
                    outputs.append(
                        result.get()
                    )

                    # remove the finished result
                    del(
                        self.presults[
                                self.presults.index(result)
                            ]
                        )

            # keep iterating should all results be cleared
              # and some still remain
            if (ready_all and self.presults) or (
                    len(self.presults) == self.config.process_count):
                sleep(.1)
                continue
            else:
                return outputs


    def do_authentication_callback(self, username, password, stop_on_valid=False, 
            *args, **kwargs):
        '''
        Call the authentication callback from a distinct process. Will monitor
        processes for completion if all are currently occupied with a previous
        callback request.
        '''

        '''
        When the maximum number of processes have been engaged
        to make authentication requests, call monitor_processes
        to watch each process until authentication finishes.

        Once completeds, the outputs are passed to handle_outputs,
        which is responsible for logging the outcome of the authentication
        request and updating the proper SQL record with the outcome.
        '''

        recovered = False
        if len(self.presults) == self.config.process_count:

            # monitor result objects
            outputs = self.monitor_processes()
            recovered = self.handle_outputs(outputs)

        if recovered and stop_on_valid:
            return recovered

        # initiate a brute in a process within the pool
        self.presults.append(
            self.pool.apply_async(
                self.config.authentication_callback,
                (
                    (username,password,)
                )
            )
        )

        return recovered

    def shutdown(self):
        '''Close & join the process pool, followed by closing input/output files.
        '''

        # =====================
        # LOG ATTACK COMPLETION
        # =====================

        self.logger.log(GENERAL_EVENTS,'Shutting attack down')

        self.attack.complete = True
        self.attack.end_time = BruteTime.current_time()
        self.main_db_sess.commit()

        self.logger.log(GENERAL_EVENTS,'Closing/joining Processes')

        if self.pool:
            self.pool.close()
            self.pool.join()

        close_all_sessions()


    def launch(self):
        """Launch a horitontal brute force attack.

        The argument to `usernames` and `passwords` are expected to
        be either a string, tuple, or list object. Should a string be
        provided, it should represent a path to a file containing
        newline delimited values of the corresponding input. Should
        a tuple or list be provided, each element should be a value
        corrsponding to the appropriate input.
        """

        if self.config.max_auth_tries:
            # Handle manually configured lockout threshold
            limit = self.config.max_auth_tries
        else:
            # Set a sane default otherwise
            limit = 1
      
        sleeping  = False # determine if the brute attack is sleeping
        recovered = False # track if a valid credentials has been recovered

        # =============================================
        # ENSURE PRIORITIZED VALUES ARE IN THE DATABASE
        # =============================================
        '''Logic iterates through each prioritized username
        and password value and determines if it resides in
        the database. A ValueError is raised if it doesn't
        exist in the database.

        Note that the password value is checked for both normal
        passwords and credentials. No error is raised so long
        as the value resides in one of the two tables.
        '''

        # ========================
        # BEGIN BRUTE FORCE ATTACK
        # ========================

        while True:

            try:

                # =======================
                # GET GUESSABLE USERNAMES
                # =======================
                '''Get a list of guessable usernames. Prioritize by:

                1. priority specifications
                2. Whether or not strict credentials have been set for
                the user
                '''
               
                # Get a list of usernames to target
                    # must not have already been recovered during an earlier attack
                    # future_time must be less than current time
                        # for that user have been completed

                usernames = self.main_db_sess.query(sql.Username) \
                        .join(sql.Credential) \
                        .filter(
                            sql.Username.recovered == False,
                            sql.Username.future_time <= time(),
                            sql.Credential.guessed == False) \
                        .order_by(sql.Username.priority.desc()) \
                        .order_by(sql.Credential.strict.desc()) \
                        .all()

                # Logging sleep events
                if not usernames and not sleeping:
                    u = self.main_db_sess.query(sql.Username) \
                        .filter(sql.Username.recovered == 0) \
                        .order_by(sql.Username.future_time.desc()) \
                        .first()
                    sleeping = True
                    if u and u.future_time > 60+time():
                        self.logger.log(
                            GENERAL_EVENTS,
                            f'Sleeping until {BruteTime.float_to_str(u.future_time)}'
                        )
                elif usernames and sleeping:
                    sleeping = False

                # =========================
                # BRUTE FORCE EACH USERNAME
                # =========================
  
                # Current limit will be used to calculate the limit of the current query
                 # used to assure that the limit remains lesser than the greatest password
                 # id
                for username in usernames:

                    # ================================
                    # GET CREDENTIALS FOR THE USERNAME
                    # ================================
                    '''Get credentials to guess for a given user. Order by:

                    1. Strict credentials
                    2. Then priority
                    '''

                    credentials = self.main_db_sess.query(sql.Credential) \
                            .join(sql.Password) \
                            .filter(
                                sql.Credential.guessed == False,
                                sql.Credential.username == username) \
                            .order_by(sql.Credential.strict.desc()) \
                            .order_by(sql.Password.priority.desc()) \
                            .limit(limit) \
                            .all()

                    # Avoid race condition
                    if username.recovered: continue 
    
                    for credential in credentials:

                        # =======================================
                        # DO THE AUTHENTICATION FOR EACH PASSWORD
                        # =======================================
   
                        # Current time of authentication attempt
                        ctime = BruteTime.current_time()

                        # Get the future time when this user can be targeted later
                        if self.config.max_auth_jitter:
                            # Derive from the password jitter
                            ftime = self.config.max_auth_jitter.get_jitter_future()
                        else:
                            # Default effectively asserting that no jitter will occur.
                            ftime = -1.0

                        # Avoid race condition
                            # also prevents checking of additional passwords if a valid
                            # password has been recovered in the distinct process
                        if username.recovered: break

                        # Update the Username/Credential object with relevant
                        # attributes and commit

                        credential.guess_time=ctime
                        credential.username.last_time=ctime
                        credential.username.future_time=ftime
                        self.main_db_sess.commit()

                        # Do the authentication callback
                        recovered = self.do_authentication_callback(
                            credential.username.value,
                            credential.password.value
                        )

                        if recovered and self.config.stop_on_valid:
                            break

                    if recovered and self.config.stop_on_valid:
                        break

                # ============================================
                # STOP ATTACK DUE TO STOP_ON_VALID_CREDENTIALS
                # ============================================
                if recovered and self.config.stop_on_valid:
                        self.logger.log(
                            GENERAL_EVENTS,
                            'Valid credentials recovered. Exiting per ' \
                            'stop_on_valid configuration.',
                        )
                        self.shutdown()
                        break

                # ===============================================
                # CONTINUE LOOPING UNTIL ALL GUESSES ARE FINISHED
                # ===============================================

                # Check if a normal credentials remains
                sample_remaining = self.main_db_sess \
                    .query(sql.Username) \
                    .join(sql.Credential) \
                    .filter(sql.Username.recovered == False,
                            sql.Credential.guessed == False) \
                    .first()

                if sample_remaining:

                    if len(self.presults):
                        outputs = self.monitor_processes()
                        self.handle_outputs(outputs)

                    sleep(.2)
                    continue

                # =======================================
                # GUESSES FINISHED; CLEAN REMINING OUTPUT
                # =======================================

                outputs = self.monitor_processes(ready_all=True)
                self.handle_outputs(outputs)
                self.logger.log(GENERAL_EVENTS,'Attack finished')
    
                # ========
                # SHUTDOWN
                # ========
   
                self.shutdown()
                break
                
            # ==================
            # EXCEPTION HANDLING
            # ==================
    
            except Exception as e:
    
                # =========================
                # DEFAULT EXCEPTION HANDLER
                # =========================
                #
                # - check if an exception handler has been provided for
                #   a given exception class
                # - if not, then shut down the brute forcer and raise
                #   the exception for the caller to handle
    
                # Allow registered handlers to trigger
                if e in self.config.exception_handlers:
    
                    self.config.exception_handlers[e](self)
    
                # Raise to caller
                else:

                    self.logger.log(
                        GENERAL_EVENTS,
                        'Unhandled exception occurred. Shutting down attack '\
                        'and returning control to the caller.'
                    )

                    self.shutdown()
                    raise e
