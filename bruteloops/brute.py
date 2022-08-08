'''
This module contains the primary logic to execute and control a brute
force attack.
'''

import traceback
import re
import signal
from calendar import monthrange
from . import logging
from .brute_time import BruteTime
from .db_manager import *
from . import queries as Queries
from .errors import BreakerTrippedError
from . import models
from sqlalchemy.orm.session import close_all_sessions
from pathlib import Path
from time import sleep, time, gmtime, strftime
from datetime import datetime, timedelta
from random import shuffle
from sys import exit
from typing import List, Callable, Any
from types import FunctionType, MethodType
from .models import Output, ExceptionHandler

UNKNOWN_PRIORITIZED_USERNAME_MSG = (
'Prioritized username value supplied during configuration that does '
'not appear in the database. Insert this value or remove it from '
'the configuration: {username}')

UNKNOWN_PRIORITIZED_PASSWORD_MSG = (
'Prioritized password value supplied during configuration that does '
'not appear in the database. Insert this value or remove it from '
'the configuration: {password}')

def wrapped_callback(func:Callable[[str,str], dict], username:str,
        password:str) -> models.Output:
    '''Implement a wrapped function to make authentication callbacks,
    enabling us to capture and act on exceptions accordingly.

    Args:
      func: A callable used to authenticate the credentials.
      username: Username to authenticate.
      password: Password to check against the user.

    Returns:
      A py::`models.Output` instance populated with output from the call to
        func.
    '''

    try:

        out = func(username, password)

        if isinstance(out, dict):

            # ==========================================
            # UPDATE WITH USERNAME/PASSWORD WHEN MISSING
            # ==========================================

            if not out.get('username', None):
                out['username'] = username
            if not out.get('password', None):
                out['password'] = password

        return out

    except Exception as e:

        # Return the output dictionary
        return Output(
            outcome=-1,
            username=username,
            password=password,
            events=[f'Handling exception: {e}'],
            exception=e
        )

def peel_credential_ids(container: Any):
    '''For each element in the container, traverse the "credential"
    relationship and collect the ID value.

    Args:
      container: Iterable of SQLAlchemy ORM instances.
    '''

    for i in range(0, len(container)):
        container[i] = container[i].credential.id

class BruteForcer:
    '''The BruteForcer object is responsible for orchestrating and
    executing a brute force attack against a target.
    '''

    def __init__(self, config:models.Config, use_billiard:bool=False):
        '''Initialize the BruteForcer object.

        Args:
          config: Initialized models.Config object.
          use_billiard: Determines if Billiard's Pool module should be
              used instead of Python's native module. Billiard's better
              handles daemonized processes.
        '''

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
            name='BruteLoops.BruteForcer', log_level=config.log_level,
            log_file=config.log_file, log_stdout=config.log_stdout,
            log_stderr=config.log_stderr, timezone=config.timezone)

        if config.timezone:
            BruteTime.set_timezone(config.timezone)

        self.log.general(f'Initializing {config.process_count} process(es)')
        
        # ===================================
        # LOG ATTACK CONFIGURATION PARAMETERS
        # ===================================

        self.log.general('Logging attack configuration parameters')

        conf_temp = 'Config Parameter -- {attr}: {val}'

        for attr in [
                'authentication_jitter', 'max_auth_jitter',
                'max_auth_tries', 'stop_on_valid',
                'db_file', 'log_file', 'log_level',
                'log_stdout', 'log_stderr', 'randomize_usernames',
                'timezone', 'blackout']:

            self.log.general(f'Config Parameter -- {attr}: ' + 
                    str(getattr(self.config,attr)))

        if hasattr(self.config.authentication_callback, 'callback_name'):
            self.log.general(f'Config Parameter -- callback_name: '+ \
                            getattr(self.config.authentication_callback,
                                'callback_name'))
            
        # =============================================================
        # REASSIGN DEFAULT SIGNAL HANDLER AND INITIALIZE A PROCESS POOL
        # =============================================================

        signal.signal(signal.SIGINT, signal.SIG_IGN)

        if use_billiard:

            import billiard
            self.pool = billiard.Pool(processes=config.process_count)

        else:

            from multiprocessing.pool import Pool
            self.pool = Pool(processes=config.process_count)

        ki_handler = None
        for eh in self.config.exception_handlers:
            if eh.exception_class == KeyboardInterrupt:
                ki_handler = eh.handler

        if not ki_handler:

            # =================================
            # DEFINE THE DEFAULT SIGINT HANDLER
            # =================================

            def handler(sig, exception):

                print('\nSIGINT Captured -- Shutting down attack\n')
                self.shutdown(complete=False)
                print('\nExiting\n')
                exit(sig)

            ki_handler = handler

            self.log.general(f'Setting default exception handler for '
                'KeyboardInterrupt')

            self.config.exception_handlers.append(
                ExceptionHandler(
                    exception_class = KeyboardInterrupt,
                    handler = handler)
            )

        # =================================
        # SET A USER-DEFINED SIGINT HANDLER
        # =================================

        signal.signal(signal.SIGINT, ki_handler)

        # =================
        # HANDLE THE ATTACK
        # =================
        
        current_time = BruteTime.current_time(format=str)
        self.log.general(f'Beginning attack: {current_time}')

        # CREATE A NEW ATTACK
        self.attack = sql.Attack(start_time=BruteTime.current_time())
        self.main_db_sess.add(self.attack)
        self.main_db_sess.commit()

        # Realign future jitter times with the current configuration
        self.realign_future_time()

    def handle_outputs(self, outputs:List[models.Output]) -> bool:
        '''Handle outputs from the authentication callback. It expects a list of
        dicts conforming to the blow format.

        Args:
          outputs: A list of dict objects matching the models.Output type.

        Returns:
          `bool` value determinine if at least one credential was valid in the
            list of outputs. This is useful when working with the "stop on valid"
            flag.
        '''

        # ==================================================
        # DETERMINE AND HANDLE VALID_CREDENTIALS CREDENTIALS
        # ==================================================

        recovered = False
        for output in outputs:

            # =====================================
            # IMPLEMENT BREAKERS/EXCEPTION HANDLERS
            # =====================================

            if output.exception is not None:

                breaker_handled, exception_handled = False, False

                # Call breakers
                for b in self.config.breakers:
                    b.check(output.exception, log=self.log)
                    if not breaker_handled:
                        breaker_handled = True

                # Pass to regular exception handlers
                for eh in self.config.exception_handlers:
                    if eh.exception_class == type(output.exception):
                        eh.handler(output.exception)
                        if not exception_handled:
                            exception_handled = True

                if breaker_handled or exception_handled:
    
                    msg = f'handled exception: {output.exception}'
    
                    if breaker_handled:
                        msg = 'Breaker ' + msg
                    else:
                        msg = 'Exception Handler ' + msg
    
                    self.log.general(msg)
    
                else:
    
                    raise output.exception

            # ===============================
            # QUERY FOR THE TARGET CREDENTIAL
            # ===============================

            credential = self.handler_db_sess \
                .query(sql.Credential) \
                .join(sql.Username) \
                .join(sql.Password) \
                .filter(
                    sql.Username.value == output.username,
                    sql.Password.value == output.password,
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

                credential.username.future_time = (
                    self
                      .config
                      .max_auth_jitter
                      .get_jitter_future())

            cred = f'{output.username}:{output.password}'

            # Handle valid credentials
            if output.outcome == 1:

                credential.guessed = True
                recovered = True
                self.log.valid(cred)

                # Update username to "recovered"
                credential.username.recovered = True

                # Update the credential to valid
                credential.valid = True

            # Guess failed for some reason
            elif output.outcome == -1:

                self.log.general(
                    f'Failed to guess credential: {cred}')

            # Credentials are no good
            else: 

                credential.guessed=True

                # Update the credential to invalid
                credential.valid=False
                self.log.invalid(cred)

            # ================================================
            # MANAGE THE ACTIONABLE ATTRIBUTE FOR THE USERNAME
            # ================================================
    
            if output.actionable and not credential.username.actionable:
                credential.username.actionable = True
            elif not output.actionable and credential.username.actionable:
                self.log.invalid_username(
                    f'Disabling invalid username - {cred}')
                credential.username.actionable = False
    
            # ===================
            # WRITE MODULE EVENTS
            # ===================
    
            for event in output.events:
                self.log.module(event)

        # Commit the changes
        self.handler_db_sess.commit()

        return recovered

    def realign_future_time(self):
        '''Iterate over each imported username value and rejitter
        the future time based on the current max_authentication_jitter

        Notes:
          - Primrily useful when strarting a brute force attack.
          - Ensures proper alignment of timestamps.
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

    def monitor_processes(self, ready_all:bool=False) -> List[models.Output]:
        '''Iterate over each process in `self.presults` and wait
        for a process to complete execution.

        Args:
          ready_all: indciates that monitoring will continue looping until all
            processes complete execution, otherwise a list of outputs
            will be returned after a single process is finished.

        Returns:
          A list of output dicts from the authentication callback.
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

    def do_authentication_callback(self, username:str, password:str,
            stop_on_valid:bool=False) -> bool:
        '''Call the authentication callback from a distinct process.
        Will monitor processes for completion if all are currently
        occupied with a previous callback request.

        Args:
            username: Username to guess.
            password: Password to guess.
            stop_on_valid: Boolean value determining if the attack
                should be halted when valid credentials are observed.

        Returns:
            Boolean value determining if a valid set of credentials
            was discovered.
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

            # ==================================
            # HANDLE WHEN ALL PROCESSES ARE BUSY
            # ==================================

            # monitor result objects
            outputs = self.monitor_processes()

            # Deteremine if at least one credential was valid.
            recovered = self.handle_outputs(outputs)

        if recovered and stop_on_valid:

            # ==============================================
            # STOP ISSUING AUTH CALLBACKS WHEN STOP ON VALID
            # ==============================================

            return recovered

        # initiate a guess in a process within the pool
        self.presults.append(
            self.pool.apply_async(
                func = wrapped_callback,
                kwds = dict(
                    func = self.config.authentication_callback,
                    username = username,
                    password = password,
                )
            )
        )

        return recovered

    def shutdown(self, complete:bool):
        '''Close & join the process pool.

        Args:
          complete: Determines if the attack was fully completed,
            i.e. all guesses were performed.
        '''

        # =====================
        # LOG ATTACK COMPLETION
        # =====================

        self.log.general('Shutting attack down')

        self.attack.complete = complete
        self.attack.end_time = BruteTime.current_time()
        self.main_db_sess.commit()

        self.log.general('Closing/joining Processes')

        if self.pool:
            self.pool.close()
            self.pool.join()

        close_all_sessions()

    def launch(self):
        '''Launch the attack.
        '''

        if self.config.max_auth_tries:

            # Handle manually configured lockout threshold
            glimit = guess_limit = self.config.max_auth_tries

        else:

            # Set a sane default otherwise
            glimit = guess_limit = 1

        if self.config.randomize_usernames:
            rand_multi = 10
        else:
            rand_multi = 1

        ulimit = user_limit = self.config.process_count
      
        last_logged  = -1    # track the last time a sleep log event was emitted
        recovered    = False # track if a valid credentials has been recovered

        # ========================
        # BEGIN BRUTE FORCE ATTACK
        # ========================

        while True:

            try:

                # ======================
                # MANAGE BLACKOUT WINDOW
                # ======================

                if self.config.blackout:

                    now = BruteTime.current_time(datetime)

                    # ==============================
                    # GET DATETIME OBJECTS FOR MATHS
                    # ==============================

                    b_start = datetime(
                        year=now.year,
                        month=now.month,
                        day=now.day,
                        hour=self.config.blackout.start.hour,
                        minute=self.config.blackout.start.minute,
                        second=self.config.blackout.start.second,
                        tzinfo=BruteTime.timezone)

                    # ========================================
                    # DETERMINE IF BLACKOUT ENDS FOLLOWING DAY
                    # ========================================

                    if (self.config.blackout.start.hour > 
                             self.config.blackout.stop.hour):
                        tomorrow = 1
                    else:
                        tomorrow = 0

                    # Future datetime variables
                    f_year = now.year
                    f_month = now.month
                    f_day = now.day + tomorrow

                    # ====================
                    # CALCULATE FUTURE DAY
                    # ====================

                    if f_day > monthrange(now.year, now.month)[1]:
                        # BlackoutModel ends in following month

                        f_month += 1
                        f_day = 1

                        if f_month > 12:
                            # BlackoutModel ends in following year
                            f_month = 1
                            f_year += 1

                    b_stop = datetime(
                        year=f_year, month=f_month, day=f_day,
                        hour=self.config.blackout.stop.hour,
                        minute=self.config.blackout.stop.minute,
                        second=self.config.blackout.stop.second,
                        tzinfo=BruteTime.timezone)

                    if (now >= b_start) and (now < b_stop):

                        # Allow outstanding processes to complete
                        outputs = self.monitor_processes(ready_all=True)
                        recovered = self.handle_outputs(outputs)
                        if recovered and self.config.stop_on_valid:
                            break

                        # =============================
                        # SLEEP THROUGH BLACKOUT WINDOW
                        # =============================

                        dstart = timedelta(hours=now.hour,
                            minutes=now.minute,
                            seconds=now.second)

                        dstop = timedelta(
                            days=tomorrow,
                            hours=self.config.blackout.stop.hour,
                            minutes=self.config.blackout.stop.minute,
                            seconds=self.config.blackout.stop.second)

                        ts = (dstop-dstart).total_seconds()
                        ft = BruteTime.future_time(seconds=ts)

                        self.log.general('Engaging blackout')
                        self.log.general(
                            'Sleeping until ' +
                            BruteTime.float_to_str(ft))

                        sleep(ts)
                        self.log.general('Disengaging blackout')

                # ========================
                # GET ACTIONABLE USERNAMES
                # ========================

                # Current time
                ctime = BruteTime.current_time()

                # PRIORITY USERNAMES
                priorities = self.main_db_sess.execute(
                        Queries.priority_usernames
                            .where(sql.Username.future_time <= ctime)
                            .limit(ulimit)
                        ).scalars().all()

                # USERNAMES WITH STRICT CREDENTIALS
                if len(priorities) < ulimit:

                    priorities += self.main_db_sess.execute(
                            Queries.strict_usernames
                                .where(
                                    sql.Username.future_time <= ctime,
                                    sql.Username.id.not_in(priorities))
                                .limit(ulimit-len(priorities))
                            ).scalars().all()

                # GET GUESSABLE USERNAMES
                if len(priorities) < ulimit:

                    # Get guessable usernames
                    guessable = self.main_db_sess.execute(
                            Queries.usernames
                                .where(
                                    sql.Username.priority == False,
                                    sql.Username.future_time <= ctime,
                                    sql.Username.id.not_in(priorities))
                                .limit(ulimit*rand_multi)
                            ).scalars().all()

                    # Randomize usernames
                    if self.config.randomize_usernames:
                        shuffle(guessable)

                    # Trim down to guessable size
                    guessable = guessable[:ulimit-len(priorities)]

                else:

                    guessable = list()

                uids = priorities + guessable

                # Logging sleep events
                if not uids:

                    ctime = BruteTime.current_time()

                    outputs = self.monitor_processes(ready_all=True)
                    recovered = self.handle_outputs(outputs)
                    if recovered and self.config.stop_on_valid:
                        break

                    q = (
                            select(sql.Username)
                                .where(
                                    sql.Username.recovered == False,
                                    sql.Username.actionable == True,
                                    sql.Username.future_time > -1,
                                    sql.Username.future_time > ctime,
                                    (
                                        (select(sql.Credential.id)
                                            .where(
                                                sql.Credential.username_id ==
                                                    sql.Username.id,
                                                sql.Credential.guessed ==
                                                    False,)
                                            .limit(1)).exists()
                                    ))
                                .order_by(sql.Username.future_time.asc())
                                .limit(1)
                        )


                    u = self.main_db_sess.execute(q) \
                        .scalars() \
                        .first()

                    if u and u.future_time:

                        sleep_time = u.future_time - ctime

                        # Log sleep events when a downtime of 60
                        # seconds or greater is observed.
                        if sleep_time >= 60:

                            self.log.general(
                                f'Sleeping until {u.value}\'s '
                                'threshold time expires: ' +
                                BruteTime.float_to_str(u.future_time))

                        if sleep_time > 0:
                            sleep(sleep_time)

                # =========================
                # BRUTE FORCE EACH USERNAME
                # =========================
  
                # Current limit will be used to calculate the limit of the current query
                 # used to assure that the limit remains lesser than the greatest password
                 # id
                for uid in uids:

                    # GET STRICT CREDENTIAL IDs
                    cids = self.main_db_sess.execute(
                        Queries.strict_credentials
                            .where(
                                sql.Credential.username_id == uid)
                            .limit(glimit)
                        ).scalars().all()

                    peel_credential_ids(cids)

                    if len(cids) < glimit:
    
                        # GET PRIORITY CREDENTIAL IDs
                        buff = self.main_db_sess.execute(
                            Queries.priority_credentials
                                .where(
                                    sql.Credential.username_id == uid,
                                    sql.Credential.id.not_in(cids),
                                )
                                .limit(glimit-len(cids))
                            ).scalars().all()

                        peel_credential_ids(buff)
                        cids += buff
    
                    if len(cids) < glimit:
    
                        # GET NORMAL CREDENTIAL IDs
                        buff = self.main_db_sess.execute(
                            Queries.credentials
                                .where(
                                    sql.Credential.username_id == uid,
                                    sql.Credential.id.not_in(cids),
                                )
                                .limit(glimit-len(cids))
                            ).scalars().all()

                        cids += buff

                    # GET THE CREDENTIALS
                    credentials = self.main_db_sess.query(sql.Credential) \
                        .filter(sql.Credential.id.in_(cids)) \
                        .all()

                    cids.clear()
    
                    shuffle(credentials)

                    # =====================
                    # GUESS THE CREDENTIALS
                    # =====================

                    for credential in credentials:

                        # Current time of authentication attempt
                        ctime = BruteTime.current_time()

                        # Get the future time when this user can be targeted later
                        if self.config.max_auth_jitter:
                            # Derive from the password jitter
                            ftime = self.config \
                                .max_auth_jitter \
                                .get_jitter_future()
                        else:
                            # Default effectively asserting that no jitter will occur.
                            ftime = -1.0

                        # ==================================
                        # DETECT POTENTIAL DUPLICATE GUESSES
                        # ==================================

                        skip_msg = None
                        if credential.username.recovered:

                            skip_msg = 'Skipping recovered credentials: ' \
                                '{username}:{password}'

                        elif credential.guess_time != -1 or credential.guessed:

                            skip_msg = 'Skipping duplicate credential guess: ' \
                                '{username}:{password}'

                        if skip_msg:

                            # ============================
                            # AVOID DUPLICATES BY SKIPPING
                            # ============================

                            self.log.general(
                                skip_msg.format(
                                    username=credential.username.value,
                                    password=credential.password.value))

                            continue

                        # Update the Username/Credential object with relevant
                        # attributes and commit

                        credential.guess_time           = ctime
                        credential.username.last_time   = ctime
                        credential.username.future_time = ftime
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
                            'stop_on_valid configuration.')
                        self.shutdown(complete=False)
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
                            sql.Credential.guess_time == -1,
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
   
                self.shutdown(complete=True)
                break
                
            # ==================
            # EXCEPTION HANDLING
            # ==================
    
            except Exception as e:
    
                if isinstance(e, BreakerTrippedError):

                    self.log.general('Exiting due to breaker trip')
                    return
    
                # Raise to caller
                self.log.general(
                    'Unhandled exception occurred. Shutting down attack '\
                    'and returning control to the caller.'
                )

                self.shutdown(complete=False)

                raise e
