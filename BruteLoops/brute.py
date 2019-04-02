#!/usr/bin/env python3

from BruteLoops.logging import *
from BruteLoops.brute_time import BruteTime
from BruteLoops import sql
from BruteLoops.config import Config
from BruteLoops.helpers import *
from sqlalchemy.orm.session import close_all_sessions
from multiprocessing.pool import Pool
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

class BruteForcer:
    '''
    DOCS HERE
    '''

    attack_type = 'DEFAULT'

    def __init__(self, config):

        if not config.validated: config.validate()

        # DB SESSION FOR MAIN PROCESS
        self.main_db_sess = config.session_maker()
        self.handler_db_sess = config.session_maker()

        # ==============================
        # BASIC CONFIGURATION PARAMETERS
        # ==============================

        self.config = config            # Config object
        self.presults = []              # Process results
        self.pool = None                # Process pool (initialized by method)
        self.attack = None
        self.logger = logging.getLogger('brute_logger')
        
        self.logger.log(
            GENERAL_EVENTS,
            f'Initializing {config.process_count} process'
        )
        
        # =============================================================
        # REASSIGN DEFAULT SIGNAL HANDLER AND INITIALIZE A PROCESS POOL
        # =============================================================
        original_sigint_handler = signal.signal(signal.SIGINT,signal.SIG_IGN)
        self.pool = Pool(processes=config.process_count)

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
        self.logger.log(GENERAL_EVENTS,f'Beginning attack: {current_time}')
        
        # NOTE: Unused at the moment. Will likely be used when additional attack types are added.
        self.attack_type = self.__class__.attack_type

        # CREATE A NEW ATTACK
        self.attack = sql.Attack(type=self.attack_type,
            start_time=BruteTime.current_time())
        self.main_db_sess.add(self.attack)
        self.main_db_sess.commit()

        self.config = config

    def handle_outputs(self, outputs):
        '''
        Handle outputs from the authentication callback. It expects a list of
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
        # DETERMINE AND HANDLE VALID_CREDENTIALS CREDENTIALS
        for output in outputs:

            username = self.handler_db_sess \
                .query(sql.Username) \
                .filter(sql.Username.value==output[1],
                    sql.Username.recovered==False) \
                .first()

            # COMPENSATE USERNAME RECENTLY BEING UPDATED TO RECOVERED
            if not username: continue

            # ======================
            # HANDLE THE CREDENTIALS
            # ======================

            cred = f'{output[1]}:{output[2]}'

            # CREDENTIALS ARE VALID_CREDENTIALS
            if output[0]:

                self.logger.log(VALID_CREDENTIALS,cred)

                password = self.handler_db_sess \
                    .query(sql.Password) \
                    .filter(sql.Password.value==output[2]) \
                    .first()

                # UPDATE USERNAME TO BE RECOVERED
                username.recovered=True
                username.last_password_id=password.id
                self.handler_db_sess.commit()

            # CREDENTIALS ARE CREDENTIAL_EVENTS
            else: 

                self.logger.log(CREDENTIAL_EVENTS,cred)

    def monitor_processes(self,ready_all=False):
        '''
        Iterate over each process in ```self.presults``` and wait for a process to
        complete execution. ```ready_all``` indciates that monitoring will continue
        looping until all processes complete execution, otherwise a list of outputs
        will be returned after a single process is finished.

        Returns a list of output objects from the ```self.authentication_callback``` function
        and the first three elements should follow the pattern below:

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


    def do_authentication_callback(self, *args):
        '''
        Call the authentication callback from a distinct process. Will monitor
        processes for completion if all are currently occupied with a pervious
        callback request.
        '''
        if len(self.presults) == self.config.process_count:

            # monitor result objects
            outputs = self.monitor_processes()
            self.handle_outputs(outputs)

        # initiate a brute in a process within the pool
        self.presults.append(
            self.pool.apply_async(
                self.config.authentication_callback,
                (
                    args
                )
            )
        )

    def import_lines(self, container, model):
        '''
        Import lines into the database.
        '''
        # source for Session.begin_nested():
        #   https://docs.sqlalchemy.org/en/latest/orm/session_transaction.html

        # TODO: Make this not suck.

        # HANDLE INPUT FILES
        if container.__class__ == str:
            with open(container) as infile:
                container = [strip_newline(line) for line in infile]

        # INSERT NEW RECORDS
        for line in container:
            try:
                with self.main_db_sess.begin_nested():
                    self.main_db_sess.merge(model(value=line))
            except Exception as e:
                self.main_db_sess.rollback()

        self.main_db_sess.commit()


    def shutdown(self):
        '''
        Close & join the process pool, followed by closing input/output files.
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

def is_iterable(obj):
    d = obj.__dir__()
    if '__iter__' in d and '__next__' in d:
        return True
    else:
        return True

class Horizontal(BruteForcer):

    attack_type = 'HORIZONTAL'

    def launch(self, usernames, passwords):
        '''
        DOCS HERE
        '''
        # ==========================
        # IMPORTING DATABASE RECORDS
        # ==========================

        if passwords.__class__ == str:
            self.import_lines(passwords,sql.Password)
        else:
            assert is_iterable(passwords),(
                'passwords must be an iterable if not a file name'
            )
            self.import_lines(passwords,sql.Password)

        if usernames.__class__ == str:
            self.import_lines(usernames,sql.Username)
        else:
            assert is_iterable(usernames),(
                'usernames must be an iterable if not a file name'
            )
            self.import_lines(usernames,sql.Username)

        self.main_db_sess.commit()
        password_count = self.main_db_sess.query(sql.Password).count()

        # ========================
        # BEGIN BRUTE FORCE ATTACK
        # ========================

        if self.config.max_auth_tries:
            # Handle manually configured lockout threshold
            limit = self.config.max_auth_tries
        else:
            # Set a sane default otherwise
            limit = 1

        # Flag used to determine if sleep events should be logged
          # triggered when no usernames are available for authentication
        log_sleep = True
        while True:

            try:

                # =======================
                # GET GUESSABLE USERNAMES
                # =======================
               
                # Get the ID of the last password in the database
                    # Used to determine if all passwords have been guessed for a
                    # given username
                final_pid = self.main_db_sess.query(sql.Password) \
                    .order_by(sql.Password.id.desc()) \
                    .limit(1) \
                    .first() \
                    .id

                # Get a list of usernames to target
                    # must not have already been recovered during an earlier attack
                    # future_time must be less than current time
                    # last_password_id cannot match the final_pid, otherwise all guesses
                        # for that user have been completed
                usernames = self.main_db_sess.query(sql.Username).filter(
                    sql.Username.recovered != True,
                    sql.Username.future_time <= time(),
                    sql.Username.last_password_id != final_pid,
                ).all()

                # =========================
                # BRUTE FORCE EACH USERNAME
                # =========================
  
                # Current limit will be used to calculate the limit of the current query
                 # used to assure that the limit remains lesser than the greatest password
                 # id
                current_limit = limit
                for username in usernames:
    
                    # ========================
                    # GET A CHUNK OF PASSWORDS
                    # ========================
    
                    # Offset represents the password id which should be targeted for the password
                    # chunk.
                    offset = username.last_password_id

                    if offset >= final_pid:
                        offset = final_pid
                        current_limit = 1
    
                    passwords = self.main_db_sess.query(sql.Password) \
                        .order_by(sql.Password.id) \
                        .offset(offset) \
                        .limit(current_limit) \
                        .all()

                    # Avoid race condition
                        # It's possible that the distinct process identified a valid username between
                        # the time that the username query was executed and the passwords were gathered
                    if username.recovered: continue 
    
                    for password in passwords:
                        # NOTE: Perhaps it'd be more efficient to move the chunked password checking
                            # to the secondary process entirely? Maybe create a different method
                            # that expects a series of passwords to attempt? Maybe even send a
                            # collection of credentials for a given process to check. The latter
                            # could potentially work well considering authentication jitter has
                            # been moved off to each child process.

                        # =======================================
                        # DO THE AUTHENTICATION FOR EACH PASSWORD
                        # =======================================
                        # NOTE: Authentication jitter is handled in each disctinct
                        # process, thus it is not expressly called here
   
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

                        # Update the Username object with relevant attributes and commit
                        username.last_password_id = password.id
                        username.last_time=ctime
                        username.future_time=ftime
                        self.main_db_sess.commit()

                        # Do the authentication callback
                        self.do_authentication_callback(
                            username.value,
                            password.value
                        )

                # ============================================
                # STOP ATTACK DUE TO STOP_ON_VALID_CREDENTIALS
                # ============================================
                if self.config.stop_on_valid and (self.main_db_sess.query(
                    sql.Username).filter(sql.Username.recovered == True).first()):
                        self.logger.log(
                            GENERAL_EVENTS,
                            'Valid credentials recovered. Exiting per '\
                            'stop_on_valid configuration.',
                        )
                        self.shutdown()
                        break

                # Assure that not all guesses have been made, based on final password id
                if self.main_db_sess \
                    .query(sql.Username) \
                    .filter(
                        sql.Username.last_password_id < final_pid,
                        sql.Username.recovered != True
                    ).first():

                    if len(self.presults):
                        outputs = self.monitor_processes()
                        self.handle_outputs(outputs)

#                        self.logger.log(
#                            GENERAL_EVENTS,
#                            'No usernames currently available for brute '\
#                            'forcing. Will resune once a duration of time'\
#                            ' has elapsed comensurate to the '\
#                            'max_auth_jitter configuration.')


                    sleep(.2)
                    continue

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
