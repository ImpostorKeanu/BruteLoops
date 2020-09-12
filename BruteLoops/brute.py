#!/usr/bin/env python3

from .logging import *
from .brute_time import BruteTime
from . import sql
from .config import Config
from sqlalchemy.orm.session import close_all_sessions
from multiprocessing.pool import Pool
from pathlib import Path
from uuid import uuid4
from collections import namedtuple
from copy import deepcopy
from time import sleep,time
from types import FunctionType, MethodType
from io import StringIO,TextIOWrapper
import traceback
import re
import signal
import logging

def strip_newline(s):
    '''Strips the final character from a string via list comprehension.
    Useful when ```str.strip()``` might pull a legitimate whitespace
    character from a password.
    '''

    if s[-1] == '\n':

        return s[:len(s)-1]

    else:

        return s

def is_iterable(obj):
    '''Check if an object has the `__iter__` and `__next__` attributes,
    suggesting it is an iterable object.
    '''

    d = obj.__dir__()
    if '__iter__' in d and '__next__' in d:
        return True
    else:
        return True

def csv_split(s,delimiter=','):
    '''Split a string on the first instance of a delimiter value.
    A tuple in the form of `(s_head,s_tail)` is returned, otherwise
    a tuple of `(None,None)` if the delimiter is not observed.
    '''

    ind=s.find(delimiter)
    if ind == -1:
        return (None,None,)

    return (s[:ind],s[ind+1:],)

class BruteForcer:
    '''Base object from which all other brute forcers will inherit.
    Provides all basic functionality, less brute force logic.
    '''

    attack_type = 'DEFAULT'

    def __init__(self, config):
        '''Initialize the BruteForcer object, including processes.

        - config - A BruteLoops.config.Config object providing all
        configuration parameters to proceed with the attack.
        '''

        if not config.validated: config.validate()

        # DB SESSION FOR MAIN PROCESS
        self.main_db_sess = config.session_maker()
        self.handler_db_sess = config.session_maker()

        # ==============================
        # BASIC CONFIGURATION PARAMETERS
        # ==============================

        self.config   = config            # Config object
        self.presults = []              # Process results
        self.pool     = None                # Process pool (initialized by method)
        self.attack   = None
        self.logger   = logging.getLogger('brute_logger')
        
        self.logger.log(
            GENERAL_EVENTS,
            f'Initializing {config.process_count} process'
        )
        
        # =============================================================
        # REASSIGN DEFAULT SIGNAL HANDLER AND INITIALIZE A PROCESS POOL
        # =============================================================

        original_sigint_handler = signal.signal(signal.SIGINT,signal.SIG_IGN)
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
        
        # NOTE: Unused at the moment. Will likely be used when
        # additional attack types are added.
        self.attack_type = self.__class__.attack_type

        # CREATE A NEW ATTACK
        self.attack = sql.Attack(type=self.attack_type,
            start_time=BruteTime.current_time())
        self.main_db_sess.add(self.attack)
        self.main_db_sess.commit()

        self.config = config

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

            username = self.handler_db_sess \
                .query(sql.Username) \
                .filter(sql.Username.value==output[1],
                    sql.Username.recovered==False) \
                .first()

            # =======================================================
            # COMPENSATE USERNAME RECENTLY BEING UPDATED TO RECOVERED
            # =======================================================

            if not username: continue

            password = self.handler_db_sess \
                .query(sql.Password) \
                .filter(sql.Password.value==output[2]) \
                .first()

            credential = self.handler_db_sess \
                .query(sql.Credential) \
                .filter(sql.Credential.username_id==username.id,
                        sql.Credential.password_id==password.id) \
                .first()

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
                username.recovered=True
                username.last_password_id=password.id

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

    def add_credential(self, csv_line, csv_delimiter=','):
        '''Parse a CSV line and add the username and passwrd
        values to the database, followed by adding the IDs to
        those values to the credential_joins table.
        '''

        username, password=csv_split(csv_line,csv_delimiter)
        # Ignore improperly formatted records
        if not username or not password:
            return None

        else:

            # Add each value to the proper table
            self.merge_lines([username],sql.Username)
            self.merge_lines([password],sql.Password)

            # Get record ids
            username = self.main_db_sess.query(sql.Username).filter(
                    sql.Username.value==username) \
                    .first() \

            password = self.main_db_sess.query(sql.Password).filter(
                    sql.Password.value==password) \
                    .first() \

            # Add the password to the username to form a
            # a credential relationship
            try:

                username.passwords.append(password)
            except Exception as e:
                self.main_db_sess.rollback()

    def merge_lines(self, container, model, is_credentials=False,
            csv_delimiter=','):
        '''Merge values from the container into the target model. If
        `is_credentials` is not `False`, then the value will be treated
        as a CSV value.
        '''

        is_file = container.__class__ == TextIOWrapper 

        for line in container:

            # Strip newlines from files
            if is_file: line = strip_newline(line)

            # Parse credentials as CSV line
            if is_credentials:

                self.add_credential(line)
                continue

            try:

                with self.main_db_sess.begin_nested():

                    self.main_db_sess.merge(model(value=line))

            except Exception as e:

                self.main_db_sess.rollback()

        self.main_db_sess.commit()

    def import_lines(self, container, model, is_file=False,
            is_credentials=False,csv_delimiter=','):
        '''Import lines into the database.
        '''
        # source for Session.begin_nested():
        #   https://docs.sqlalchemy.org/en/latest/orm/session_transaction.html

        if is_file:
            with open(container) as container:
                self.merge_lines(container, model, is_credentials)
        else:
            self.merge_lines(container, model, is_credentials)

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

    def import_values(self, usernames=None, passwords=None,
            username_files=None, password_files=None,
            credentials=None, credential_files=None,
            csv_delimiter=','):
        '''Check each supplied value to determine if it's iterable
        and proceed to import each record of the container into
        the brute force database.
        '''

        # ===============
        # VALIDATE INPUTS
        # ===============

        for v in [usernames,passwords,username_files,password_files,
                credentials,credential_files]:
            if is_iterable(v): continue
            raise ValueError(
                    'Username/Password arguments must be iterable values ' \
                    'populated with string records or file names'
                )

        # =================
        # IMPORT THE VALUES
        # =================

        if passwords:
            self.import_lines(passwords,sql.Password)

        if usernames:
            self.import_lines(usernames,sql.Username)

        if credentials:
            self.import_lines(credentials,None,False,True,csv_delimiter)

        if username_files:
            for f in username_files:
                self.import_lines(f,sql.Username,True)

        if password_files:
            for f in password_files:
                self.import_lines(f,sql.Password,True)

        if credential_files:
            for f in credential_files:
                self.import_lines(f,None,True,True,csv_delimiter)

        self.main_db_sess.commit()


class Spray(BruteForcer):

    attack_type = 'SPRAY'

    def import_values(self, *args, **kwargs):

        # =========================================
        # IMPORT VALUES INTO THE DATABASE VIA SUPER
        # =========================================

        super().import_values(*args, **kwargs)

        # ====================================================
        # CREATE A CREDENTIAL FOR EACH USERNAME:PASSWORD COMBO
        # ====================================================

        passwords = self.main_db_sess.query(sql.Password).all()
        for u in self.main_db_sess.query(sql.Username).all():
            u.passwords=passwords

    def launch(self, usernames=None, passwords=None,
            username_files=None, password_files=None,
            credentials=None, credential_files=None,
            csv_delimiter=','):
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
        
        self.import_values(usernames=usernames,
                passwords=passwords, username_files=username_files,
                password_files=password_files, credentials=credentials,
                credential_files=credential_files,
                csv_delimiter=csv_delimiter)

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
               
                # Get a list of usernames to target
                    # must not have already been recovered during an earlier attack
                    # future_time must be less than current time
                    # last_password_id cannot match the final_pid, otherwise all guesses
                        # for that user have been completed
                usernames = self.main_db_sess.query(sql.Username) \
                    .join(sql.Credential) \
                    .filter(
                        sql.Username.recovered == False,
                        sql.Username.future_time <= time(),
                        sql.Credential.guessed == False,) \
                    .all()

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
                for username in usernames:
    
                    # ========================
                    # GET A CHUNK OF PASSWORDS
                    # ========================
    
                    credentials = self.main_db_sess \
                            .query(sql.Credential) \
                            .filter(sql.Credential.username_id==username.id,
                                    sql.Credential.guessed==False) \
                            .limit(limit) \
                            .all()

                    # Avoid race condition
                        # It's possible that the distinct process identified a valid username between
                        # the time that the username query was executed and the passwords were gathered
                    if username.recovered: continue 
    
                    for credential in credentials:
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
                        credential.username.last_password_id = credential.password.id
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


                if self.main_db_sess \
                    .query(sql.Username) \
                    .join(sql.Credential) \
                    .filter(sql.Username.recovered == False,
                            sql.Credential.guessed == False) \
                    .first():

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

class Credential(Spray):
    '''Perform a credential style brute force attack. Only credentials
    supplied in the form of CSV delimited records will be attempted.
    Logic to perform the overall attack is inherited from `Spray`
    since it now uses a distinct table to track `Credential` objects.
    This class overrides the `import_values` method and overrides it
    to limit the creation of `Credential` objects to only the records
    that appear in the `credential` and `credential_files` arguments.
    '''

    attack_type = 'CREDENTIAL'

    def import_values(self, credentials=None, credential_files=None,
            csv_delimiter=',', *args, **kwargs):
        '''Import credential records into the target database. A
        one-to-many relationship is established between each user
        and their corressponding passwords.

        - credentials - A list of CSV delimited values, i.e. `username,
        password`
        - credential_files - A list of string values associated with
        file names on the local filesystem to be parsed into CSV records
        - csv_delimiter - The CSV separator value used to split each
        value of `credentials` or `credential_files`.
        '''

        if args or [v for k,v in kwargs.items() if v != None]:
            raise ValueError(
                'Credential attack accepts only credentials or ' \
                'credential_file arguments to assure that each ' \
                'username value is associated with specific ' \
                'password values'
            )

        # TODO: super kept confusing me here so I just tapped right into
        # __mro__ so I can move on with my fucking life
        Credential.__mro__[2].import_values(self,
                credentials=credentials,
                credential_files=credential_files,
                csv_delimiter=csv_delimiter)
