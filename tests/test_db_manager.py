import pytest
import pdb
from sqlalchemy import (
    select,
    func
)
from bruteloops import sql, models, db_manager
from typing import (
    Union,
    List,)
from pathlib import Path
from uuid import uuid4 as UUID

def cb(username, password):
    raise Exception('Intentional failure')
CONFIG = dict(authentication_callback=cb)

class InvalidRowCountError(Exception):
    pass

def gen_values(prefix:str, count:int, credentials:bool=False,
        cred_del=':', tmp_path:Union[Path, None]=None,
        uuid:bool=False) -> List[str]:
    '''Dynamically generate database values.

    Args:
        prefix: Prefix appended to each value.
        count: The number of records to generate.
        credentials: Determines if credential values should be
            generated.
        cred_del: Delimiter to use when generating credentials.
        tmp_path: Path to the directory where values should be
            written to disk. Ignored when set to None.
        uuid: Determines if UUID values should be generated.

    Returns:
        - List of str when not tmp_path is None
        - List of str paths pointing to generated files
    '''

    if tmp_path is not None:
        tmp_file = tmp_path / f'{prefix}_values.txt'
        values = tmp_file.open('w+')
    else:
        tmp_file = None
        values = list()

    # ===================
    # GENERATE THE VALUES
    # ===================

    for n in range(1, count+1):

        if uuid == True:
            n = f'-{n}-{str(UUID())}'

        if credentials:
            # Create a credential to be parsed
            v = f'cu{n}{cred_del}cp{n}'
        else:
            # Just a standard input value
            v = prefix+str(n)

        if tmp_file:
            values.write(v+'\n')
        else:
            values.append(v)

    if tmp_file:
        values.close()
        return [tmp_file]

    return values

def insert_values(config:models.Config, dbm:db_manager.Manager,
        data_type:str, count:int=1, credentials:bool=False,
        associate_spray:bool=False,
        cred_del:str=':', uuid:bool=False, check_rows:bool=True):
    '''Use BL.db_manager.Manager to insert records directly into a
    database. Logic will also check to make sure that the proper number
    of values have been inserted.

    Args:
        config: Config object to reference.
        dbm: Manager instance used to interface with the database.
        data_type: Datatype to generate. Valid options:
            userername, password, credential
        count: Count of values to insert.
        associate_spray: Determines if spray values should be
            associated.
        credentials: Determines if the values should be treated as
            strict credentials. Relevant only when the data_type value
            is set to credential.
        check_rows: Determines if rows should be checked.

    Raises:
        - InvalidRowCountError when an invalid number of rows is observed
          after the insert.
    '''

    valid_types = ('username','password','credential',)
    if not data_type in valid_types:
        raise ValueError(
            f'Invalid data type supplied: {data_type}. '
            f'Allowed: {", ".join(valid_types)}'
        )

    handle = f'insert_{data_type}_records'

    # Generate values for the method call
    values = gen_values(data_type[0], count,
            credentials=(data_type == 'credential'),
            cred_del=cred_del, uuid=uuid)

    # Kwargs for the method call
    kwargs = dict(
        container=values,
        associate_spray_values=associate_spray)

    # Update kwargs for credential method calls
    if data_type == 'credential':
        kwargs.update(
            dict(
                as_credentials = not associate_spray
            )
        )

    # Call the method
    getattr(dbm, handle)(**kwargs)

    # Count the inserted values
    table = getattr(sql, data_type.capitalize())

    if check_rows:

        count_rows(
            dbm,
            table,
            count*(count if credentials and associate_spray else 1))

    return values

def insert_via_manage(config:models.Config, dbm:db_manager.Manager,
        data_type:str, count:int=1, associate_spray:bool=False,
        tmp_path:Path=None, uuid:bool=False, check_rows:bool=True):
    '''Insert username and password values via manage_values. All
    arguments mirror insert_values.
    '''

    model = sql.Username
    if data_type == 'username':
        model = sql.Password

    values = gen_values(data_type[0], count, tmp_path=tmp_path,
            uuid=uuid)

    dbm.manage_values(model=model, container=values,
        is_file=True if tmp_path is not None else False,
        associate_spray_values=associate_spray)

    if check_rows:
        count_rows(dbm, model, count)

def credentials_via_manage(config:models.Config,
        dbm:db_manager.Manager, insert:bool=True,
        count:int=1, credentials:bool=False,
        associate_spray:bool=False, tmp_path:Path=None,
        uuid:bool=False, check_rows:bool=True):
    '''Insert credentials via manage_credentials. All arguments mirrior
    insert_values.
    '''

    values = gen_values('c', count, tmp_path=tmp_path, uuid=uuid, credentials=True)
    dbm.manage_credentials(container=values,
        insert=insert,
        is_file=(True if tmp_path else False),
        associate_spray_values=associate_spray,
        as_credentials=credentials)

    if check_rows:
        count_rows(dbm, sql.Credential, count)

def count_rows(dbm, table, expected_count):

    out = dbm.main_db_sess.query(
            func.count(
                table.id
            )
        ).scalar()

    if not out or out != expected_count:
        raise InvalidRowCountError(
            f'Incorrect count of records returned. Got: {out}, '
            f'Expected: {expected_count}')

# =========================
# INSERT INDIVIDUAL RECORDS
# =========================

def test_insert_usernames(setup):

    config, dbm = setup
    insert_values(config, dbm, 'username', count=10)

def test_insert_passwords(setup):

    config, dbm = setup
    insert_values(config, dbm, 'password', count=10)

def test_insert_strict_credentials(setup):

    config, dbm = setup
    insert_values(config,
        dbm, 'credential', count=10,
        credentials=True)

def test_insert_spray_credentials(setup):

    config, dbm = setup
    insert_values(config,
        dbm, 'credential', count=10,
        credentials=True, associate_spray=True)

def test_associate_all_values(setup):

    ucount = 10
    pcount = 5

    config, dbm = setup
    insert_values(config, dbm, 'username', count=ucount)
    insert_values(config, dbm, 'password', count=pcount)

    with pytest.raises(InvalidRowCountError):
        # Records aren't associated yet, so this should raise
        # an exception.
        count_rows(dbm, sql.Credential, ucount*pcount)

    # Associate the records
    dbm.associate_spray_values()
    count_rows(dbm, sql.Credential, ucount*pcount)

# =========================
# INSERT VIA MANAGE RECORDS
# =========================

def test_insert_usernames_via_manage(setup):

    config, dbm = setup
    insert_via_manage(config, dbm, 'username', count=10)

def test_insert_values_via_file(setup, tmp_path):

    config, dbm = setup
    insert_via_manage(config, dbm, 'username', count=10, tmp_path=tmp_path)
    insert_via_manage(config, dbm, 'password', count=10, tmp_path=tmp_path,
        associate_spray=True)
    count_rows(dbm, sql.Credential, 100)

def test_insert_passwords_via_manage(setup):

    config, dbm = setup
    insert_via_manage(config, dbm, 'password', count=10)

def test_associate_after_manage_passwords(setup):

    ucount = 30
    pcount = 5

    config, dbm = setup

    insert_via_manage(config, dbm, 'username', count=ucount)
    insert_via_manage(config, dbm, 'password', count=pcount,
        associate_spray=True)
    count_rows(dbm, sql.Credential, (ucount*pcount))

def test_manage_credentials(setup):

    count = 100
    fcount = 10
    config, dbm = setup

    # Insert and count the records
    credentials_via_manage(config, dbm, count=count,
            credentials=True)
    values = credentials_via_manage(config, dbm, count=fcount,
            credentials=True, check_rows=False, uuid=True)
    count_rows(dbm, sql.Credential, (count+fcount))

    # Delete a record and make sure it's updated accordingly
    credentials_via_manage(config, dbm, count=1,
           credentials=True, check_rows=False, insert=False)
    count_rows(dbm, sql.Credential, (count+fcount)-1)
