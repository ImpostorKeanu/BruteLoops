import pytest
import bruteloops as BL

@pytest.fixture
def config_kwargs(tmp_path):

    return dict(
        db_file=str((tmp_path / 'tmp.db').absolute()),
        process_count=1,
        max_auth_tries=1,
        authentication_jitter=dict(min='0.1s', max='0.1s'),
        max_auth_jitter=dict(min='1s', max='1.2s'),
        stop_on_valid=False,
        log_level='invalid-usernames',
        timezone='America/New_York',
        blackout=dict(start='06:40', stop='06:41'),
        breakers=[
            dict(exception_classes=[Exception], threshold=5)
        ],
        exception_handlers=[
            dict(exception_class=Exception, handler=lambda a: print(a))])

@pytest.fixture
def setup(request, config_kwargs):
    '''This fixture will set up a BL.models.Config model while creating
    and initializing a database.

    Notes:
        - See test_breakers.py for examples on setting these values!
        - Ways to update values passed to the Config model by:
            - Set a module-level dictionary variable to CONFIG
            - Set an attribute to a function test case to CONFIG
        - Ways to call db_manager functions:
            - Set a module-level dictionary variable to DBM_CALLBACKS
            - Set an attribute to a function test case to DBM_CALLBACKS
        - DBM_CALLBACKS structure:
            - This should be like: {<method_name>:<kwargs>}
            - ONLY KWARGS ARE SUPPORTED!
    '''

    # ==============================================
    # UPDATE THE CONFIG KWARGS AND GENERATE A CONFIG
    # ==============================================

    config_kwargs.update(getattr(request.module, 'CONFIG', dict()))
    config_kwargs.update(getattr(request.function, 'CONFIG', dict()))
    config = BL.models.Config(**config_kwargs)

    # =======================================
    # CREATE DATABASE AND APPLY DBM FUNCTIONS
    # =======================================

    dbm = BL.db_manager.Manager(config.db_file)
    for handle in ('module', 'function',):
        handle = getattr(request, handle)
        dbm_callbacks = getattr(handle, 'DBM_CALLBACKS', dict())

        # Run each of the DBM callbacks
        for fhandle, kwargs in dbm_callbacks.items():
            if kwargs is None: kwargs = dict()
            getattr(dbm, fhandle)(**kwargs)

    return config, dbm
