from .logging import *
from pathlib import Path
from . import sql
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from io import StringIO,TextIOWrapper

# Components needed to manage usenames and passwords in database files

'''
# Purpose

This enables us to move away from the original approach of having
the attack, in terms of importing and exporting users and passwords,
manage database records.

# Questions

- Can a distinct script read and write to a database while an attack
is underway?
  - What issues will this cause?
  - It'd be nice to be able to just allow an attack to continue while
    managing the underlying records.

# Capabilities

- Create database
- Insert
  - usernames
  - passwords
  - credentials
- Delete
  - usernames
  - passwords
  - credentials
'''

def strip_newline(s):
    '''Strips the final character from a string via list comprehension.
    Useful when ```str.strip()``` might pull a legitimate whitespace
    character from a password.
    '''

    if s[-1] == '\n': return s[:len(s)-1]
    else: return s

def is_iterable(obj):
    '''Check if an object has the `__iter__` and `__next__` attributes,
    suggesting it is an iterable object.
    '''

    d = obj.__dir__()
    if '__iter__' in d and '__next__' in d: return True
    else: return True

def csv_split(s,delimiter=','):
    '''Split a string on the first instance of a delimiter value.
    A tuple in the form of `(s_head,s_tail)` is returned, otherwise
    a tuple of `(None,None)` if the delimiter is not observed.
    '''

    ind=s.find(delimiter)
    if ind == -1: return (None,None,)
    return (s[:ind],s[ind+1:],)

class DBMixin:

    def merge_lines(self, container, model, is_credentials=False,
            csv_delimiter=':'):
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

                self.add_credential(line, csv_delimiter)
                continue

            try:

                with self.main_db_sess.begin_nested():

                    self.main_db_sess.merge(model(value=line))

            except Exception as e:

                self.main_db_sess.rollback()

        self.main_db_sess.commit()

    def import_records(self, container, model, is_file=False,
            is_credentials=False, csv_delimiter=':'):
        '''Import lines into the database.
        '''
        # source for Session.begin_nested():
        #   https://docs.sqlalchemy.org/en/latest/orm/session_transaction.html

        if is_file:
            with open(container) as container:
                self.merge_lines(container, model, is_credentials,
                        csv_delimiter)
        else:
            self.merge_lines(container, model, is_credentials,
                    csv_delimiter)

    def delete_records(self, container, model, is_file=False,
            is_credentials=False, csv_delimiter=':'):

        if is_file:
            with open(container) as container:
                self.delete_lines(container, model, is_credentials,
                        csv_delimiter)
        else:
            self.delete_lines(container, model, is_credentials,
                    csv_delimiter)

    def delete_lines(self, container, model, is_credentials=False,
            csv_delimiter=':'):
        '''Delete lines from `container`.
        '''

        is_file = container.__class__ == TextIOWrapper

        for line in container:

            # Strip newlines from file values
            if is_file: line = strip_newline(line)

            # Call delete_credential on credential records
            if is_credentials:
                self.delete_credential(line, csv_delimiter)
                continue

            try:

                # Delete the target value
                value = self.main_db_sess.query(model) \
                        .filter(model.value == line) \
                        .first()

                if value: self.main_db_sess.delete(value)

            except Exception as e:
                self.logger.log(GENERAL_EVENTS, e)
                pass
                #self.main_db_sess.rollback()

        self.main_db_sess.commit()

    def delete_credential(self, csv_line, csv_delimiter=':'):
        '''Parse a credential `csv_line` and delete both the username
        and password values.
        '''

        username, password = csv_split(csv_line,csv_delimiter)

        if not username or not password:
            return None

        self.delete_lines([username],sql.Username)
        self.delete_lines([password],sql.Password)

    def add_credential(self, csv_line, csv_delimiter=':'):
        '''Parse a CSV line and add the username and passwrd
        values to the database, followed by adding the IDs to
        those values to the credential_joins table.
        '''

        username, password=csv_split(csv_line,csv_delimiter)
        # Ignore improperly formatted records
        if not username or not password: return None


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

    def insert_values(self, usernames=None, passwords=None,
            username_files=None, password_files=None,
            credentials=None, credential_files=None,
            csv_delimiter=':', as_credentials=False):
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

        # Make sure that only credential inputs are allowed when the
        # as_credentials flag is set to true
        if as_credentials:
            
            msg = 'Only credentials or credential_files can be supplied ' \
                  'when using the as_credentials flag is set to True'
            
            if usernames or passwords or username_files or \
                    password_files: raise ValueError(msg)

        # =================
        # IMPORT THE VALUES
        # =================

        # Record the last username and password ids for future use
        last_pass = self.main_db_sess.query(sql.Password) \
                .order_by(sql.Password.id.desc()).first()

        last_user = self.main_db_sess.query(sql.Username) \
                .order_by(sql.Username.id.desc()).first()

        if last_pass: last_pass = last_pass.id
        else: last_pass = 0

        if last_user: last_user = last_user.id
        else: last_user = 0

        # import passwords from list
        if passwords:
            self.import_records(passwords,sql.Password)

        # import usernames from list
        if usernames:
            self.import_records(usernames,sql.Username)

        # import usernames from files
        if username_files:
            for f in username_files:
                self.import_records(f,sql.Username,True)

        # import passwords from files
        if password_files:
            for f in password_files:
                self.import_records(f,sql.Password,True)

        # import credentials from list
        if credentials:
            self.import_records(credentials,None,False,True,csv_delimiter)

        # import credentials from files
        if credential_files:
            for f in credential_files:
                self.import_records(f,None,True,True,csv_delimiter)

        self.main_db_sess.commit()

        # ============================
        # PREPARE DB FOR SPRAY ATTACKS
        # ============================
        '''Spray attacks associate each provided password with each
        username, where credential attacks maintain a record of username
        to password association based on input.
        '''

        # Associate all new usernames to new passwords if we're importing
        # for a spray attack
        if not as_credentials:

            # Handle new database case
            if last_pass == 0 and last_user == 0:

                passwords = self.main_db_sess.query(sql.Password).all()
                for u in self.main_db_sess.query(sql.Username).all():
                    u.passwords = passwords

            else:

                passwords = self.main_db_sess.query(sql.Password) \
                        .filter(sql.Password.id > last_pass) \
                        .all()

                for u in self.main_db_sess.query(sql.Username) \
                        .filter(sql.Username.id > last_user) \
                        .all():

                    u.passwords = passwords

        self.main_db_sess.commit()

    def get_valid_credentials(self):
        '''Return valid credentials
        '''

        return self.main_db_sess.query(sql.Credential) \
                .filter(sql.Credential.valid == True) \
                .all()

    def delete_values(self, usernames=None, passwords=None,
            username_files=None, password_files=None,
            credentials=None, credential_files=None,
            csv_delimiter=':', as_credentials=False):
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

        # Make sure that only credential inputs are allowed when the
        # as_credentials flag is set to true
        if as_credentials:
            
            msg = 'Only credentials or credential_files can be supplied ' \
                  'when using the as_credentials flag is set to True'
            
            if usernames or passwords or username_files or \
                    password_files: raise ValueError(msg)

        # =================
        # DELETE THE VALUES
        # =================

        # import passwords from list
        if passwords:
            self.delete_records(passwords,sql.Password)

        # import usernames from list
        if usernames:
            self.delete_records(usernames,sql.Username)

        # import usernames from files
        if username_files:
            for f in username_files:
                self.delete_records(f,sql.Username,True)

        # import passwords from files
        if password_files:
            for f in password_files:
                self.delete_records(f,sql.Password,True)

        # import credentials from list
        if credentials:
            self.delete_records(credentials,None,False,True,csv_delimiter)

        # import credentials from files
        if credential_files:
            for f in credential_files:
                self.delete_records(f,None,True,True,csv_delimiter)

        self.main_db_sess.commit()

class Manager(DBMixin):

    def __init__(self, db_file):
        self.session_maker = Session(db_file)
        self.main_db_sess = self.session_maker.new()
        self.logger = logging.getLogger('brute_logger')
        
class Session:
    # TODO: This will replace the session creation logic in BruteLoops.config.validate

    def __init__(self, db_file):
        '''Initialize a session object.
        '''

        # =====================
        # SQLITE INITIALIZATION
        # =====================
        engine = create_engine('sqlite:///'+db_file)
        Session = sessionmaker()
        Session.configure(bind=engine)

        # Create the database if required
        if not Path(db_file).exists():
            sql.Base.metadata.create_all(engine)

        self.session = Session

    def new(self):
        '''Create and return a new session.
        '''

        return self.session()
