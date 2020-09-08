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
from io import StringIO
import traceback
import re
import signal
import logging
import csv

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
        recovered = False
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

                recovered = True
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

        return recovered

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

class Credential(BruteForcer):
    attack_type = 'CREDENTIAL'

    def merge_lines(self,container):
        """Merge credential lines from an iterable container
        into the target SQLite database.
        """

        for tup in container:
            try:
                with self.main_db_sess.begin_nested():
                    self.main_db_sess.merge(
                            sql.Credential(username=tup[0],
                                password=tup[1]))
            except Exception as e:
                self.main_db_sess.rollback()

    def import_lines(self,container,csv_delimiter=","):
        """Import lines into a database from a CSV file.
        """


        # String values are associated with files on disk
        if container.__class__ == str:
            with open(container) as container:
                self.merge_lines(
                    csv.reader(container,delimiter=csv_delimiter)
                )

        # Anything else is considered an iterable
        else:
            self.merge_lines(
                csv.reader(container,csv_delimiter)
            )

    def handle_outputs(self,outputs):
        """Handle output from an authentication request by logging
        the outcome and updating the target SQLite database record.
        """

        recovered = False
        for output in outputs:

            credential = self.handler_db_sess \
                    .query(sql.Credential) \
                    .filter(sql.Credential.username==output[1],
                            sql.Credential.password==output[2]) \
                    .first()

            cred = f'{output[1]}:{output[2]}'

            if output[0]:

                recovered = True
                self.logger.log(VALID_CREDENTIALS,cred)
                credential.recovered=True
                self.handler_db_sess.commit()

            else:

                self.logger.log(CREDENTIAL_EVENTS,cred)

        return recovered

    def launch(self, credentials):
        """Launch the credential brute force attack.
        """

        # =======================
        # IMPORT DATABASE RECORDS
        # =======================

        valid_types = [str,list,tuple]
        assert credentials.__class__ in valid_types,(
            'Password list must be a str, list, or tuple'
        )

        self.import_lines(credentials)
        self.main_db_sess.commit()

        # ================
        # START THE ATTACK
        # ================

        try:
    
            for credential in self.main_db_sess.query(sql.Credential) \
                    .filter(sql.Credential.recovered==False,
                            sql.Credential.guess_time==-1.0):
                credential.guess_time = BruteTime.current_time()
                recovered = self.do_authentication_callback(
                        credential.username, credential.password,
                        stop_on_valid=self.config.stop_on_valid)
        
            outputs = self.monitor_processes(ready_all=True)
            self.handle_outputs(outputs)
            self.logger.log(GENERAL_EVENTS,'Attack finished')
            self.shutdown()

        except Exception as e:

            if e in self.config.exception_handlers:

                self.config.exception_handlers[e](self)

            else:

                self.logger.log(
                    GENERAL_EVENTS,
                    'Unhandled exception occurred. Shutting down attack ' \
                    'and returning control to the caller.'
                )

                self.shutdown()
                raise e

class Horizontal(BruteForcer):

    attack_type = 'HORIZONTAL'

    def launch(self, usernames, passwords):
        """Launch a horitontal brute force attack.

        The argument to `usernames` and `passwords` are expected to
        be either a string, tuple, or list object. Should a string be
        provided, it should represent a path to a file containing
        newline delimited values of the corresponding input. Should
        a tuple or list be provided, each element should be a value
        corrsponding to the appropriate input.
        """

        # ==========================
        # IMPORTING DATABASE RECORDS
        # ==========================

        valid_types = [str,list,tuple]
        assert passwords.__class__ in valid_types,(
            'Password list must be a str, list, or tuple'
        )
        assert usernames.__class__ in valid_types,(
            'Username list must be a str, list, or tuple'
        )

        self.import_lines(passwords,sql.Password)
        self.import_lines(usernames,sql.Username)
        self.main_db_sess.commit()

        # ========================
        # BEGIN BRUTE FORCE ATTACK
        # ========================
        password_count = self.main_db_sess.query(sql.Password).count()
        if self.config.max_auth_tries:
            # Handle manually configured lockout threshold
            limit = self.config.max_auth_tries
        else:
            # Set a sane default otherwise
            limit = 1
       
        sleeping  = False # determine if the brute attack is sleeping
        recovered = False # track if a valid credentials has been recovered
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

                # Logging sleep events
                if not usernames and not sleeping:
                    u = self.main_db_sess.query(sql.Username) \
                        .filter(sql.Username.recovered == 0) \
                        .order_by(sql.Username.future_time.desc()) \
                        .first()
                    sleeping = True
                    if u:
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
                        # process, thus it is not expressly called here. See logic
                        # that sets the authentication callback in BruteLoops.config
                        # for how this process works.
   
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
                        recovered = self.do_authentication_callback(
                            username.value,
                            password.value
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
