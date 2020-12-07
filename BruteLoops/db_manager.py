from .logging import *
from pathlib import Path
from . import sql
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from io import StringIO,TextIOWrapper
from sys import stderr

# Components needed to manage usenames and passwords in database files
logging.basicConfig(format=FORMAT, level=logging.DEBUG, stream=stderr)

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

    def merge_lines(self, container, model):
        '''Merge values from the container into the target model. If
        `is_credentials` is not `False`, then the value will be treated
        as a CSV value.
        '''

        is_file = container.__class__ == TextIOWrapper 

        for line in container:

            # Strip newlines from files
            if is_file: line = strip_newline(line)

            self.logger.debug(f'Adding value to database: {line}')

            try:

                with self.main_db_sess.begin_nested():

                    self.main_db_sess.merge(model(value=line))

            except Exception as e:

                self.main_db_sess.rollback()

        self.main_db_sess.commit()

    def delete_lines(self, container, model):
        '''Delete lines from `container`.
        '''

        is_file = container.__class__ == TextIOWrapper

        for line in container:

            # Strip newlines from file values
            if is_file: line = strip_newline(line)

            self.logger.debug(
                    f'Deleting value from database: {line}')

            try:

                # Delete the target value
                value = self.main_db_sess.query(model) \
                        .filter(model.value == line) \
                        .first()

                if value: self.main_db_sess.delete(value)

            except Exception as e:
                
                self.main_db_sess.rollback()

        self.main_db_sess.commit()

    def manage_values(self, model, container, is_file=False, insert=True):
        '''Manage username values by iterating over a target container.
        The action taken for the container is indicated by the `insert`
        parameter, which is set to `True` by default. Setting this
        value to `False` results in each username being deleted from
        the database.
        '''

        # Derive the target method to call based on action
        method = ('insert' if insert else 'delete') + '_' + \
                ('username' if model == sql.Username else 'password') +\
                '_records'
        
        # Call the proper method
        if is_file:
            for f in container:
                with open(f) as container:
                    getattr(self, method)(container)
        else: getattr(self, method)(container)

    # ===========================
    # USERNAME MANAGEMENT METHODS
    # ===========================

    def insert_username_records(self, container):
        '''Insert each username value in the container into the target
        database. Duplicates will not be inserted.
        '''

        self.merge_lines(container, sql.Username)
        

    def delete_username_records(self, container):
        '''Delete each username value in the container from the target
        database. Values that do not exist in the database are ignored.
        '''

        self.delete_lines(container, sql.Username)

    # ===========================
    # PASSWORD MANAGEMENT METHODS
    # ===========================

    def insert_password_records(self, container):
        '''Insert individual password records. Additional processing must
        occur on individual passwords in order to make the associations
        with username values.

        Warning: This method assumes that the container has spray records,
        resulting in each password being associated with each username in
        the form of a potential credential.
        '''

        # Add all the new passwords
        self.merge_lines(container, sql.Password)

        self.main_db_sess.commit()

    def delete_password_records(self, container):
        '''Delete each password value in the ocntainer from the target
        database. Values that do not exist in the database are ignored.
        '''

        self.delete_lines(container, sql.Password)

    # =============================
    # CREDENTIAL MANAGEMENT RECORDS
    # =============================

    def manage_credentials(self, container, is_file=False,
            as_credentials=False, insert=True):
        '''Manage credential values. This logic is distinct because inputs
        can be treated as individual username or password values for
        spray attacks, or as individual credential records -- the latter
        meaning that the username and password will each be inserted into
        the proper tables BUT will result in only a single credential record
        in credentials table.

        as_credentials indicates if each record is considered a credential.
        When False, the record is considered an individual username and
        password value and will be used in the form of a spray. When True,
        it is imported as a strict credential as described above.
        '''
        # Derive the target method to call based on action
        method = ('insert' if insert else 'delete') + '_credential_records'
    
        # Caall the proper method
        if is_file:
            for f in container:
                with open(f) as container:
                    getattr(self, method)(container, as_credentials)
        else: getattr(self, method)(container, as_credentials)

    def insert_credential_records(self, container, as_credentials=False,
            credential_delimiter=':'):
        '''Insert credential records into the database. If as_credentials
        is True, then only StrictCredential records will be created
        for each username to password value. Records will otherwise be
        treated as spray values, resulting in each supplied password being
        set for guess across all usernames.
        '''

        is_file = container.__class__ == TextIOWrapper
        
        for line in container:

            # Strip newlines if we're working with a file
            if is_file: line = strip_newline(line)

            self.logger.debug(
                    f'Inserting credential into database: {line}')

            # Break out the username and password value from the csv
            # delimiter value
            username, password = csv_split(line, credential_delimiter)

            if as_credentials:

                # ===========================
                # CREATE THE STRICTCREDENTIAL
                # ===========================

                # Get or create the target username
                username = self.goc(sql.Username, username)

                # Create a new strict credential record
                scred = sql.StrictCredential(username=username,
                        password=password)

                # Try to save the credential record
                try:
                    self.main_db_sess.add(scred)
                    self.main_db_sess.commit()
                except Exception as e:
                    # Assume the record already exists
                    self.main_db_sess.rollback()

                # =============================
                # REMOVE MATCHING SPRAY RECORDS
                # =============================
                '''
                We do this because BruteLoops will favor StrictCredentials
                over normal Credentials.                
                '''

                password = self.main_db_sess.query(sql.Password) \
                        .filter(sql.Password.value == password) \
                        .first()

                if password:

                    cred = self.main_db_sess.query(sql.Credential) \
                        .filter(sql.Username == username,
                                sql.Password == password) \
                        .first()

                    if cred: self.main_db_sess.delete(cred)

            else:

                # ==============================
                # INSERT THE VALUES FOR SPRAYING
                # ==============================

                self.insert_username_records([username])
                self.insert_password_records([password])

    def delete_credential_records(self, container, as_credentials=False,
            credential_delimiter=':'):
        '''Delete credential records from the target database.
        '''

        is_file = container.__class__ == TextIOWrapper
        
        for line in container:

            if is_file: line = strip_newline(line)

            self.logger.debug(
                    f'Deleting credential from database: {line}')

            username, password = csv_split(line, credential_delimiter)

            # ==================================
            # GET THE USERNAME FROM THE DATABASE
            # ==================================

            username = self.main_db_sess.query(sql.Username) \
                    .filter(sql.Username.value == username) \
                    .first()

            if not username:
                self.logger.debug(
                        f'Username not found in database: {username}')
                continue

            # ===============================
            # HANDLE STRICT CREDENTIAL RECORD
            # ===============================

            if as_credentials:

                # Query for the strict credential
                scred = self.main_db_sess.query(sql.StrictCredential) \
                        .filter(
                            sql.StrictCredential.username == username,
                            sql.StrictCredential.password == password) \
                        .first()

                # Manage the static credential
                if scred:

                    if len(scred.username.credentials) == 0:

                        # Remove the username entirely if no additional
                        # guesses are available
                        self.main_db_sess.delete(scred.username)

                    else:

                        self.main_db_sess.delete(scred)

                    self.main_db_sess.commit()

            # ===================
            # HANDLE SPRAY VALUES
            # ===================

            else:

                self.delete_username_records([username])
                self.delete_password_records([password])

    def get_or_create(self, model, value):
        '''Get or create an individual database instance, the return
        value.
        '''

        instance = self.main_db_sess.query(model) \
                .filter(model.value == value) \
                .first()

        if instance: return instance
        else:
            instance = model(value=value)
            self.main_db_sess.add(instance)
            self.main_db_sess.commit()
            return instance

    def goc(self, *args, **kwargs):
        '''Shortcut to get_or_create.
        '''

        return self.get_or_create(*args, **kwargs)

    def manage_db_values(self, insert=True, usernames=None,
            passwords=None, username_files=None, password_files=None,
            credentials=None, credential_files=None,
            credential_delimiter=':', as_credentials=False):

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

        if not usernames and not username_files and \
                not passwords and not password_files and \
                not credentials and not credential_files:
            self.logger.debug('No values to manage supplied to db manager')
            return

        # ===============
        # BEGIN EXECUTION
        # ===============

        self.logger.debug(f'Starting db management. Action: ' + \
                ('INSERT' if insert else 'DELETE'))

        # ===================
        # HANDLE SPRAY VALUES
        # ===================

        if usernames:
            self.logger.debug(f'Managing usernames: {usernames}')
            self.manage_values(sql.Username, usernames, insert=insert)
        if passwords:
            self.logger.debug(f'Managing passwords: {passwords}')
            self.manage_values(sql.Password, passwords, insert=insert)

        if username_files:
            self.logger.debug(f'Managing username files: {username_files}')
            self.manage_values(sql.Username, username_files,
                    is_file=True, insert=insert)
        if password_files:
            self.logger.debug(f'Managing password files: {password_files}')
            self.manage_values(sql.Password, password_files,
                    is_file=True, insert=insert)

        # ========================
        # HANDLE CREDENTIAL VALUES
        # ========================

        if credentials:
            self.logger.debug(f'Managing credentials: {credentials}')
            self.manage_credentials(credentials,
                    as_credentials=as_credentials, insert=insert)

        if credential_files:
            self.logger.debug(
                    f'Managing credential files: {credential_files}')
            self.manage_credentials(credential_files,
                    is_file=True, as_credentials=as_credentials,
                    insert=insert)

        # ==========================================
        # REASSOCIATE SPRAY PASSWORDS WITH USERNAMES
        # ==========================================

        # Get all passwords
        passwords = self.main_db_sess.query(sql.Password).all()

        # Associate the passwords with each user
        for u in self.main_db_sess.query(sql.Username) \
                .filter(sql.Username.recovered != True) \
                .all():

            u.passwords = passwords

        self.main_db_sess.commit()

    def get_valid_credentials(self):
        '''Return valid credentials
        '''

        # Normal credentials
        valids = self.main_db_sess.query(sql.Credential) \
                .filter(sql.Credential.valid == True) \
                .all()

        # Static credentials
        valids += self.main_db_sess.query(sql.StaticCredential) \
                .filter(sql.StaticCredential.valid == True) \
                .all()

        return valids

    def get_strict_credentials(self,credential_delimiter=':'):
        '''Return strict credential records
        '''

        return self.main_db_sess.query(sql.StrictCredential).all()

class Manager(DBMixin):

    def __init__(self, db_file):
        self.session_maker = Session(db_file)
        self.main_db_sess = self.session_maker.new()
        self.logger = logging.getLogger('BruteLoops.db_manager')
        
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
