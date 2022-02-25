from . import sql
from . import logging
from pathlib import Path
from sqlalchemy import (
    create_engine,
    select,
    update,
    delete,
    join,
    not_,
    func,
    event)
from sqlalchemy.orm import sessionmaker, aliased
from sqlalchemy.dialects.sqlite import insert
from io import StringIO,TextIOWrapper
from sys import stderr
from functools import wraps
from inspect import signature
import csv
import re

RE_USERNAME = re.compile('username',re.I)
RE_PASSWORD = re.compile('password',re.I)

logger = logging.getLogger('BruteLoops.db_manager',
        log_level=10)

def check_container(f):

    s = signature(f)

    @wraps(f)
    def wrapper(*args, container, **kwargs):

        if 'is_file' in s.parameters.keys() and container and \
                'is_file' not in kwargs.keys():

            kwargs['is_file'] = isinstance(container, TextIOWrapper)

        if 'is_dictreader' in s.parameters.keys() and container and \
                'is_dictreader' not in kwargs.keys():

            kwargs['is_dictreader'] = isinstance(container, csv.DictReader)

        return f(container=container, *args, **kwargs)

    return wrapper

def scan_dictreader(container, as_credentials) -> (str, str,):

    # Iterate over each field name and find the username
    # and password field
    username_key, password_key = None, None
    for k in container.fieldnames:
        if username_key and password_key: break
        elif re.match(RE_USERNAME,k): username_key = k
        elif re.match(RE_PASSWORD,k): password_key = k

    # Ensure that there's a username and password key
    # in the header field
    if as_credentials and not username_key or \
            not password_key:

        raise ValueError(
            'CSV file must have "username" and "password" '
            'word field in the first line of the CSV file '
            'in order to map the inputs properly. Skipping'
            ' CSV file. Current fields: '
            f'{container.fieldnames}')

    elif not username_key and not password_key:

        raise ValueError(
            'CSV file must have at least a "username" or '
            '"password" field in the first line of the'
            ' CSV file in order to map the inputs '
            'properly. Skipping CSV file.')

    return username_key, password_key

def flatten_dict_values(a):
    for i in range(0, len(a)):
        a[i] = a[i]['value']

def split_credential_container(container:list, username_key:bool=None,
        password_key:bool=None, credential_delimiter=':',
        as_credentials=False, non_cred_format=dict) -> (dict, list, list,):
    '''Split a container of credential values into three containers and
    return them.

    Args:
        container: A container of credential values to handle.
        username_key: When working on a csv.DictReader object, the header
          for the username column.
        password_key: When working on a csv.DictReader object, the header
          for the password column.
        as_credentials: Determines if the values should be strict credentials.
        credential_delimiter: Character/sequence used to delimit username and
          password values.
        non_cred_format: Dictates the output format of non-credential values,
          i.e. usernames or passwords. Expects either `dict` or `list`. When
          `dict` is supplied, password values will also include the proper
          "sprayable" attribute value in accordance with the value supplied
          for `as_credentials`. In both cases, `dict` format produces a
          structure like `{"value":"username or password"}`, making `dict`
          the most suitable input when preparing to insert records. When
          `list` is supplied, a list of string values will be returned.

    Returns:
        A tuple:
            - Element 1: dictionary of credential values, organized by username.
            - Element 2: A list of username or dictionary values.
            - Element 3: A list of password or dictionary values.
    '''

    is_dictreader = isinstance(container, csv.DictReader)

    if is_dictreader and (not username_key or not password_key):

        raise ValueError(
            'username_key and username_key required when operating '
            'on csv.DictReader objects.')

    credentials, usernames, passwords = {}, [], []
    while container:

        value = container.pop(0)

        if is_dictreader or (username_key and password_key):

            # Parsed from CSV library because we have a reader
            username, password = (value[username_key],
                value[password_key],)

        else:

            # Parsed as a non-standard CSV value
            username, password = csv_split(value,
                    credential_delimiter)

        # ================================
        # CAPTURE USERNAME/PASSWORD VALUES
        # ================================

        if username:

            # Capture the username value
            usernames.append(dict(value = username))

        if password:

            # Capture the password value
            passwords.append(dict(value = password,
                sprayable = not as_credentials))

        if as_credentials and username and password:

            # ============================
            # AGGREGATE CREDENTIAL RECORDS
            # ============================

            if not username in credentials:

                # Track new username
                credentials[username] = [password]

            elif username in credentials and not \
                    password in credentials[username]:

                # Insert new password for username
                credentials[username].append(password)

    return credentials, usernames, passwords

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

@check_container
def chunk_container(container, callback,
        is_file:bool=False, threshold:int=100000, cargs:tuple=None,
        ckwargs:dict=None):
    '''Break a container of items down into chunks and pass them
    to a callback for further processing. Particularly useful when
    inserting/upserting records into a database.

    Args:
        container: An iterable containing values to act upon.
        callback: A callback that will receive the chunked values
          from container.
        is_file: Boolean value indicating if the records are
          originating from a file. If so, newlines are stripped.
        threshold: The maximum number of records to pass back to
          `callback`.
        cargs: Positional arguments passed to `callback`.
        ckwargs: Keyword arguments passed to `callback.
    '''

    cargs = cargs if cargs is not None else tuple()
    ckwargs = ckwargs if ckwargs is not None else dict()

    chunk = []
    for v in container:

        if is_file and isinstance(v,str):

            # Strip newlines from file strings
            v = strip_newline(v)

        # Append the item to the chunk
        chunk.append(v)

        if len(chunk) == threshold:
            # Call the callback for the chunk
            callback(*cargs, chunk=chunk, **ckwargs)
            chunk.clear()

    if chunk:
        # Process any remaining chunks
        callback(*cargs, chunk=chunk, **ckwargs)

    if is_file and hasattr(container,'seek'):
        # Seek any containers back to 0
        container.seek(0)

class DBMixin:

    def do_upsert(self, model, values:list,
            index_elements:list=['value'],
            do_update_where:str=None, update_data:str=None):

        # https://docs.sqlalchemy.org/en/14/dialects/sqlite.html#insert-on-conflict-upsert
        s = insert(model).values(values)

        if do_update_where and update_data:

            # TODO: Perform checks on do_update where
            # must be a query, I think.

            if not isinstance(update_data, dict):
                raise ValueError(
                    f'update_data must be a dictionary of data')

            s = s.on_conflict_do_update(
                index_elements=index_elements,
                where=do_update_where,
                set_=update_data)

        else:

            s = s.on_conflict_do_nothing(
                index_elements=index_elements)

        try:

            with self.main_db_sess.begin_nested():
                self.main_db_sess.execute(s)

        except Exception as e:

            logger.debug(f'Failed to upsert values: {e}')
            self.main_db_sess.rollback()

    def delete_lines(self, container, model):
        '''Delete lines from `container`.
        '''

        def _delete_values(chunk):

            self.main_db_sess.execute(
                delete(model)
                    .where(model.value.in_(chunk)))
            self.main_db_sess.commit()

        chunk_container(
            container = container,
            callback = _delete_values)

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
                    getattr(self, method)(container=container)

        else: getattr(self, method)(container=container)

    # ===========================
    # USERNAME MANAGEMENT METHODS
    # ===========================

    def insert_username_records(self, container):
        '''Insert each username value in the container into the target
        database. Duplicates will not be inserted.
        '''

        def _upsert_values(chunk):

            self.do_upsert(
                model = sql.Username,
                values = [dict(value = v) for v in chunk])

            self.main_db_sess.commit()
            self.associate_spray_values(username_values=chunk)

        chunk_container(container = container,
            callback = _upsert_values)
        
    def delete_username_records(self, container):
        '''Delete each username value in the container from the target
        database. Values that do not exist in the database are ignored.
        '''

        self.delete_lines(container=container, model=sql.Username)

    def disable_username_records(self, container):
        '''Set the actionable attribute on each record in the container
        to False, removing them from further guesses.
        '''

        self.main_db_sess.execute(
            update(sql.Username)
                .where(
                    sql.Username.value.in_(container),
                    sql.Username.actionable == True)
                .values(actionable = False))

        self.main_db_sess.commit()

    def enable_username_records(self, container):
        '''Set the actionable attribute on each record in the container
        to True, ensuring they will be targeted for further guesses.
        '''

        self.main_db_sess.execute(
            update(sql.Username)
                .where(
                    sql.Username.value.in_(container),
                    sql.Username.actionable == False)
                .values(actionable = True))

        self.main_db_sess.commit()

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

        def _upsert_values(chunk):
            '''Upsert password values.

            Function ensures that password values inserted are treated
            as spray values. Should a known password be supplied in
            chunk and that password's "sprayable" attribute be set to
            False, it will be updated to True.
            '''

            self.do_upsert(
                model = sql.Password,
                values = [dict(value=v) for v in chunk],
                do_update_where = (sql.Password.sprayable == False),
                update_data = dict(sprayable = True))

            self.main_db_sess.commit()
            self.associate_spray_values(password_values=chunk)

        chunk_container(
            container = container,
            callback = _upsert_values)

    def associate_spray_values(self, username_values=None,
            password_values=None):
        '''Create records in the credentials association table for
        spray values.

        Args:
            username_values: A list of username values to associate.
            password_values: A list of string password values to
              associate.
        '''

        AND_TEMP = ' AND {table}.value IN ("{values}")'

        logger.debug('Associating spray values.')

        # TODO: Update this to use the ORM. It's complicated though.
        query = ('INSERT INTO credentials '
            '(username_id, password_id, valid, strict, guessed, guess_time) '
            'SELECT usernames.id, passwords.id, false, false, false, -1 '
            'FROM usernames, passwords '
            'WHERE passwords.sprayable = true'
            ' AND usernames.recovered = false')

        if username_values:

            query += AND_TEMP.format(
                    table='usernames',
                    values=','.join(username_values))

        if password_values:

            query += AND_TEMP.format(
                    table='passwords',
                    values=','.join(password_values))

        query += ' ON CONFLICT DO NOTHING;'

        self.main_db_sess.execute(query)
        self.main_db_sess.commit()

        logger.debug('Finished associating spray values.')

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
                with open(f, newline='') as container:
                    reader = csv.DictReader(container)
                    getattr(self, method)(container=reader,
                        as_credentials=as_credentials)

        elif is_file:
            for f in container:
                with open(f) as container:
                    getattr(self, method)(container=container,
                        as_credentials=as_credentials)

        else: getattr(self, method)(container=container,
                as_credentials=as_credentials)

    @check_container
    def insert_credential_records(self, container, as_credentials=False,
            credential_delimiter=':', is_file=False, is_dictreader=False):
        '''Insert credential records into the database. If as_credentials
        is True, then only StrictCredential records will be created
        for each username to password value. Records will otherwise be
        treated as spray values, resulting in each supplied password being
        set for guess across all usernames.
        '''

        # =================================
        # PREPARE KEY FIELDS FOR CSV INPUTS
        # =================================

        if is_file: container.seek(0)

        username_key, password_key = None, None
        if is_dictreader:
            username_key, password_key = scan_dictreader(container, as_credentials)

        def _upsert_values(chunk):

            # ======================================
            # BREAK THE RECORDS DOWN INTO CONTAINERS
            # ======================================

            credentials, usernames, passwords = \
                split_credential_container(chunk,
                    username_key=username_key,
                    password_key=password_key,
                    credential_delimiter=credential_delimiter,
                    as_credentials=as_credentials)

            # ================
            # UPSERT USERNAMES
            # ================

            self.do_upsert(model = sql.Username,
                values = usernames)

            if as_credentials:

                # Free up memory
                del(usernames)

            # ================
            # UPSERT PASSWORDS
            # ================

            # Upsert the passwords
            if as_credentials:

                # Non-sprayable passwords
                self.do_upsert(model = sql.Password,
                    values = passwords)

            else:

                # Sprayable passwords
                  # Also updates currently existing non-sprayable passwords
                  # to become sprayable.
                self.do_upsert(model = sql.Password,
                    values = passwords,
                    do_update_where = sql.Password.sprayable == False,
                    update_data=dict(sprayable = True))

            if as_credentials:

                # Free up memory
                del(passwords)

            else:

                # Commit current database changes
                self.main_db_sess.commit()

                flatten_dict_values(usernames)
                flatten_dict_values(passwords)

                # Associate the newly inserted values
                self.associate_spray_values(
                    username_values=usernames,
                    password_values=passwords)

                # Skip credential associations by returning
                return

            # ===============================
            # CREATE CREDENTIAL RECORD VALUES
            # ===============================

            values = []
            for username in list(credentials.keys()):

                passwords = credentials[username]
                del(credentials[username])

                # ===============================
                # CREATE CREDENTIAL RECORD VALUES
                # ===============================

                username = self.main_db_sess.query(sql.Username) \
                    .filter(sql.Username.value == username) \
                    .first()

                for password in self.main_db_sess.query(sql.Password) \
                        .filter(sql.Password.value.in_(passwords)):

                    values.append(dict(
                        username_id = username.id,
                        password_id = password.id,
                        strict = True))

            # =============================
            # UPSERT THE CREDENTIAL RECORDS
            # =============================

            self.do_upsert(model = sql.Credential,
                values = values,
                index_elements=['username_id', 'password_id'])

        chunk_container(container = container,
            callback = _upsert_values,
            is_file = not is_dictreader and is_file)

        self.main_db_sess.commit()


    @check_container
    def delete_credential_records(self, container,
            as_credentials:bool=False,
            credential_delimiter:str=':', is_file:bool=False,
            is_dictreader:bool=False):
        '''Delete credential records from the target database.
        '''

        if is_file: container.seek(0)

        username_key, password_key = None, None

        if is_dictreader:

            username_key, password_key = scan_dictreader(container,
                as_credentials)

        def _delete_values(chunk):

            credentials, usernames, passwords = \
                split_credential_container(chunk,
                    username_key=username_key,
                    password_key=password_key,
                    as_credentials=as_credentials)

            if as_credentials:

                # ==========================
                # DESTROY CREDENTIAL RECORDS
                # ==========================

                del(usernames)
                del(passwords)

                ids = []
                for username in list(credentials.keys()):

                    # ================================
                    # COLLECT CREDENTIALS FOR THE USER
                    # ================================

                    ids += [
                        i.id for i in
                        self.main_db_sess.query(sql.Credential) \
                            .join(sql.Username) \
                            .join(sql.Password) \
                            .filter(
                                sql.Username.value == username,
                                sql.Password.value.in_(
                                    credentials[username]),
                                sql.Credential.guessed == False)
                    ]

                # ======================
                # APPLY THE DELETE QUERY
                # ======================

                self.main_db_sess.execute(
                    delete(sql.Credential)
                        .where(sql.Credential.id.in_(ids)))

                self.main_db_sess.commit()


            else:

                # ================================
                # DESTROY USERNAME/PASSWORD VALUES
                # ================================

                flatten_dict_values(usernames)
                flatten_dict_values(passwords)

                if usernames:

                    self.delete_lines(
                        container=usernames,
                        model=sql.Username)

                if passwords:

                    self.delete_lines(
                        container=passwords,
                        model=sql.Password)

        chunk_container(
            container = container,
            callback = _delete_values)

        self.main_db_sess.commit()

        # =======================================
        # DELETE ORPHANED NON-SPRAYABLE PASSWORDS
        # =======================================

        aPass = aliased(sql.Password)
        aCred = aliased(sql.Credential)

        query = select(sql.Password.id) \
            .select_from(sql.Password) \
            .select_from(
                join(sql.Password, sql.Credential)) \
            .where(
                sql.Password.sprayable == False,
                not_(
                    select(sql.Credential.password_id)
                        .where(aPass.id == aCred.password_id)
                        .exists()))

        # Get the password ids
        ids = self.main_db_sess.execute(query).all()

        if ids:

            # Flatten the row tuples
            for i in range(0, len(ids)):
                ids[i] = ids[i][0]

            # Delete the records
            self.main_db_sess.execute(
                delete(sql.Password)
                    .where(sql.Password.id.in_(ids)))

        self.main_db_sess.commit()

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

    goc = get_or_create

    def manage_priorities(self, usernames:list=None,
            passwords:list=None, prioritize:bool=False):
        '''Prioritize or deprioritize database values.

        Args:
            usernames: A list of string username values.
            passwords: A list of string password values.
            prioritize: Boolean determining if the values should be
              prioritized or deprioritized.
        '''

        if not usernames and not passwords:
            raise ValueError('usernames or passwords required')

        usernames = usernames if usernames != None else []
        passwords = passwords if passwords != None else []

        if usernames:

            # Manage username priorities
            self.main_db_sess.execute(
                update(sql.Username)
                    .where(
                        sql.Username.value.in_(usernames))
                    .values(priority = True))

        if passwords:

            # Manage password priorities
            self.main_db_sess.execute(
                update(sql.Password)
                    .where(
                        sql.Password.value.in_(passwords))
                    .values(priority = True))

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

def _fk_pragma_on_connect(dbapi_con, con_record):
    dbapi_con.execute('pragma foreign_keys=ON')

class Session:

    def __init__(self, db_file, echo=False):
        '''Initialize a session object.
        '''

        # =====================
        # SQLITE INITIALIZATION
        # =====================

        engine = create_engine('sqlite:///'+db_file,echo=echo)

        event.listen(engine, 'connect', _fk_pragma_on_connect)

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
