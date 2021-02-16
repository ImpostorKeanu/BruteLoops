import BruteLoops
from pathlib import Path
from . import sql
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from io import StringIO,TextIOWrapper
from sys import stderr
import csv
import re

RE_USERNAME = re.compile('username',re.I)
RE_PASSWORD = re.compile('password',re.I)

logger = BruteLoops.logging.getLogger('BruteLoops.db_manager',
        log_level=10)

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
        if is_file: container.seek(0)

        for line in container:

            # Strip newlines from files
            if is_file: line = strip_newline(line)

            #logger.debug(f'Adding value to database: {line}')

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
        if is_file: container.seek(0)

        for line in container:

            # Strip newlines from file values
            if is_file: line = strip_newline(line)

            #logger.debug(
            #        f'Deleting value from database: {line}')

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
        self.associate_spray_values(container, sql.Username)

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
        self.associate_spray_values(container, sql.Password)

    def associate_spray_values(self, container, container_sql_class):

        # Seek back to the beginning of any file containers
        is_file = container.__class__ == TextIOWrapper
        if is_file: container.seek(0)

        # ===========================================
        # ASSOCIATE PASSWORD VALUES BACK TO USERNAMES
        # ===========================================

        if container_sql_class == sql.Username:

            logger.debug(
                'Associating usernames to passwords')

            for line in container:
    
                if is_file: line = strip_newline(line)

                # ================
                # GET THE USERNAME
                # ================
    
                username = self.main_db_sess.query(container_sql_class) \
                        .filter(
                            (sql.Username.value == line) &
                            (sql.Username.recovered == False)
                        ) \
                        .first()

                if not username: continue

                # ==================================
                # GET AND ASSOCIATE TARGET PASSWORDS
                # ==================================
                '''

                Outer join is used here so that all passwords are
                  returned that are not associated with any credentials
                  along with any passwords that are associated with
                  credentials but are strict only to the target username

                Filter notes:

                - Require that the passwords have an id, obviously
                - Only non-strict credentials, unless the strict
                  credential is for the current username
                '''

#                passwords = self.main_db_sess \
#                    .query(sql.Password) \
#                    .outerjoin(sql.Credential) \
#                    .filter(
#                        (sql.Password.credentials == None) | 
#                        ((sql.Password.id != None) &
#                        (
#                            (sql.Credential.strict == False) |
#                            (
#                                (sql.Credential.username == username) &
#                                (sql.Credential.strict == True)
#                            )
#                        ))
#                    ).all()
#
#                username.passwords = passwords

                username.passwords += self.main_db_sess.query(sql.Password) \
                    .outerjoin(sql.Credential) \
                    .filter(
                        (sql.Password.credentials == None) | 
                            (
                                (sql.Password.id != None) & 
                                (sql.Credential.strict == False) &
                                (sql.Credential.username != username)
                            )
                    ).all()

            logger.debug(
                'Finished associating usernames to passwords')

        # ===========================================
        # ASSOCIATE USERNAMES BACK TO PASSWORD VALUES
        # ===========================================

        else:

            logger.debug(
                'Associating passwords to usernames')

            # =========================
            # GET VALID USERNAME VALUES
            # =========================
            '''
            - Omit recovered usernames
            '''

            usernames = self.main_db_sess \
                .query(sql.Username) \
                .filter(sql.Username.recovered == False) \
                .all()

            for line in container:
    
                if is_file: line = strip_newline(line)

                # =============================
                # GET THE TARGET PASSWORD VALUE
                # =============================
    
                password = self.main_db_sess \
                    .query(sql.Password) \
                    .filter(sql.Password.value == line) \
                    .first()

                if not password: continue

                password.usernames = usernames
    
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
            as_credentials=False, insert=True, is_csv_file=False):
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
    
        # Call the proper method
        if is_csv_file:
            for f in container:
                with open(f) as container:
                    reader = csv.DictReader(container)
                    getattr(self, method)(reader, as_credentials)

        elif is_file:
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

        # =================================
        # PREPARE KEY FIELDS FOR CSV INPUTS
        # =================================

        USERNAME_KEY, PASSWORD_KEY, IS_DICTREADER = None, None, False
        if container.__class__ == csv.DictReader:

            IS_DICTREADER = True

            # Iterate over each field name and find the username
            # and password field
            for k in container.fieldnames:
                if USERNAME_KEY and PASSWORD_KEY: break
                elif re.match(RE_USERNAME,k): USERNAME_KEY = k
                elif re.match(RE_PASSWORD,k): PASSWORD_KEY = k

            # Ensure that there's a username and password key
            # in the header field
            if as_credentials and not USERNAME_KEY or \
                    not PASSWORD_KEY:

                raise ValueError(
                    'CSV file must have "username" and "password" ' \
                    'word field in the first line of the CSV file ' \
                    'in order to map the inputs properly. Skipping' \
                    ' CSV file. Current fields: ' \
                    f'{container.fieldnames}'
                )

            elif not USERNAME_KEY and not PASSWORD_KEY:

                raise ValueError(
                    'CSV file must have at least a "username" or ' \
                    '"password" field in the first line of the' \
                    ' CSV file in order to map the inputs ' \
                    'properly. Skipping CSV file.'
                )


        is_file = container.__class__ == TextIOWrapper
        if is_file: container.seek(0)

        usernames = []        
        for line in container:

            #logger.debug(
            #        f'Inserting credential into database: {line}')

            # Strip newlines if we're working with a file
            if not IS_DICTREADER and is_file:
                line = strip_newline(line)

            # ====================================
            # GET THE USERNAME AND PASSWORD VALUES
            # ====================================

            if IS_DICTREADER:

                # Collect the username and password value from the line
                username = line[USERNAME_KEY]
                password = line[PASSWORD_KEY]

            else:

                # Break out the username and password value from the csv
                # delimiter value
                username, password = csv_split(line,
                        credential_delimiter)

            if as_credentials:

                # ===========================
                # CREATE THE STRICTCREDENTIAL
                # ===========================

                # Get or create the target username
                new, username = self.goc(sql.Username, username)

                #if new: usernames.append(username.value)

                new, password = self.goc(sql.Password, password)

                # Look up the credential
                credential = self.main_db_sess.query(sql.Credential) \
                        .join(sql.Username) \
                        .join(sql.Password) \
                        .filter(
                            sql.Username.id == username.id,
                            sql.Password.id == password.id
                        ).first()

                # If it's there, then we save it as strict
                if credential and not credential.strict:

                    credential.strict = True
                    self.main_db_sess.commit()

                else:

                    # Create a new strict credential record
                    cred = sql.Credential(username=username,
                            password=password,
                            strict=True)

                    # Try to save the credential record
                    try:
                        self.main_db_sess.add(cred)
                        self.main_db_sess.commit()
                    except Exception as e:
                        # Assume the record already exists
                        self.main_db_sess.rollback()

            else:

                # ==============================
                # INSERT THE VALUES FOR SPRAYING
                # ==============================
                self.insert_username_records([username])
                self.insert_password_records([password])

        if as_credentials and usernames:
            self.associate_spray_values(usernames, sql.Username)

    def delete_credential_records(self, container, as_credentials=False,
            credential_delimiter=':'):
        '''Delete credential records from the target database.
        '''

        is_file = container.__class__ == TextIOWrapper
        if is_file: container.seek(0)
        
        for line in container:

            if is_file: line = strip_newline(line)

            #logger.debug(
            #    f'Attempting to delete credential from database: {line}'
            #)

            username, password = csv_split(line, credential_delimiter)

            credential = self.main_db_sess.query(sql.Credential) \
                    .join(sql.Username) \
                    .join(sql.Password) \
                    .filter(
                        sql.Username.value == username,
                        sql.Password.value == password) \
                    .first()

            if not credential:
                logger.debug(
                    'Credential not found in database: {}:{}' \
                    .format(username,password)
                )
                continue

            # ===============================
            # HANDLE STRICT CREDENTIAL RECORD
            # ===============================

            if as_credentials and credential.strict:

                # Remove orphaned usernames
                if len(credential.username.credentials) == 1:
                    logger.debug(
                        'Removing final credential for ' \
                        f'{credential.username.value}. Username will ' \
                        'be removed as well since no additional ' \
                        'guesses are scheduled'
                    )
                    self.main_db_sess.delete(credential.username)

                # Remove the credential
                else:
                    logger.debug(
                        'Removing credential: {}:{}'.format(
                            credential.username.value,
                            credential.password.value
                        )
                    )
                    self.main_db_sess.delete(credential)

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

        if instance:
            return False, instance
        else:
            instance = model(value=value)
            self.main_db_sess.add(instance)
            self.main_db_sess.commit()
            self.main_db_sess.flush()
            return True, instance

    def goc(self, *args, **kwargs):
        '''Shortcut to get_or_create.
        '''

        return self.get_or_create(*args, **kwargs)

    def manage_priorities(self, usernames=None, passwords=None,
            prioritize=False):

        if not usernames and not passwords:
            raise ValueError('usernames or passwords required')

        usernames = usernames if usernames != None else []
        passwords = passwords if passwords != None else []

        for model,container in {sql.Username:usernames,
                sql.Password:passwords}.items():

            for value in container:

                record = self.main_db_sess.query(model) \
                        .filter(model.value == value) \
                        .first()

                if record:
                    logger.debug(
                        f'Setting priority ({prioritize}) for: ' \
                        f'{record.value}'
                    )
                    record.priority = prioritize
                else:
                    logger.debug(
                        f'Record value not found: {value}'
                    )

        self.main_db_sess.commit()

    def manage_db_values(self, insert=True, usernames=None,
            passwords=None, username_files=None, password_files=None,
            credentials=None, credential_files=None,
            credential_delimiter=':', as_credentials=False,
            csv_files=None):

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
                not credentials and not credential_files and \
                not csv_files:
            logger.debug('No values to manage supplied to db manager')
            return

        # ===============
        # BEGIN EXECUTION
        # ===============

        logger.debug(f'Starting db management. Action: ' + \
                ('INSERT' if insert else 'DELETE'))

        # ===================
        # HANDLE SPRAY VALUES
        # ===================

        if usernames:
            logger.debug(f'Managing usernames: {usernames}')
            self.manage_values(sql.Username, usernames, insert=insert)

        if passwords:
            logger.debug(f'Managing passwords: {passwords}')
            self.manage_values(sql.Password, passwords, insert=insert)

        if username_files:
            logger.debug(f'Managing username files: {username_files}')
            self.manage_values(sql.Username, username_files,
                    is_file=True, insert=insert)

        if password_files:
            logger.debug(f'Managing password files: {password_files}')
            self.manage_values(sql.Password, password_files,
                    is_file=True, insert=insert)

        # ========================
        # HANDLE CREDENTIAL VALUES
        # ========================

        if credentials:
            logger.debug(f'Managing credentials: {credentials}')
            self.manage_credentials(credentials,
                    as_credentials=as_credentials, insert=insert)

        if credential_files:
            logger.debug(
                    f'Managing credential files: {credential_files}')
            self.manage_credentials(credential_files, is_file=True,
                    as_credentials=as_credentials, insert=insert)

        if csv_files:
            logger.debug(
                    f'Managing CSV credential files: {csv_files}')
            self.manage_credentials(csv_files, is_csv_file=True,
                    as_credentials=as_credentials, insert=insert)

    def get_valid_credentials(self):
        '''Return valid credentials
        '''

        # Normal credentials
        valids = self.main_db_sess.query(sql.Credential) \
                .filter(sql.Credential.valid == True) \
                .all()

        return valids

    def get_strict_credentials(self,credential_delimiter=':'):
        '''Return strict credential records
        '''

        return self.main_db_sess.query(sql.Credential) \
                .filter(sql.Credential.strict == True) \
                .all()

class Manager(DBMixin):

    def __init__(self, db_file):
        self.session_maker = Session(db_file)
        self.main_db_sess = self.session_maker.new()
        
class Session:

    def __init__(self, db_file, echo=False):
        '''Initialize a session object.
        '''

        # =====================
        # SQLITE INITIALIZATION
        # =====================

        engine = create_engine('sqlite:///'+db_file,echo=echo)
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
