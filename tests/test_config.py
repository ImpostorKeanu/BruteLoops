import pytest
import bruteloops as BL
from bruteloops.models import *
from bruteloops import db_manager
from bruteloops.brute import BruteForcer
from uuid import uuid4
from pathlib import Path

def cback(username, password):

    outcome = dict(
        outcome=0,
        username=username,
        password=password)

    if username == 'u3' and password == 'p2':
        outcome['outcome'] = 1

    return outcome

def test_config_model(config_kwargs):

    config_kwargs['authentication_callback'] = cback
    config_kwargs['process_count'] = 'bad'

    with pytest.raises(ValueError):
        Config(**config_kwargs)

    config_kwargs['process_count'] = 1

    config = Config(**config_kwargs)

    dbm = db_manager.Manager(config.db_file)

    dbm.insert_username_records(['u1', 'u2', 'u3'], False)
    dbm.insert_password_records(['p1', 'p2', 'p3', 'p4', 'p5'], False)
    dbm.associate_spray_values()

    BruteForcer(config=config).launch()    
