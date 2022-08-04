import pytest
import bruteloops as BL
from pathlib import Path
from time import sleep

class FakeError(Exception):
    pass

def cb(username, password):
    raise FakeError('Fake')

def test_breaker():

    breaker = BL.models.Breaker(
        exception_classes=[FakeError])
    with pytest.raises(BL.errors.BreakerTrippedError):
        breaker.check(FakeError('Testo'))

def test_threshold_breaker():

    t = 5

    breaker = BL.models.ThresholdBreaker(threshold=t,
        count=0,
        exception_classes=[FakeError])

    fake = FakeError('Testo')

    with pytest.raises(BL.errors.BreakerTrippedError):
        for n in range(0,t+1):
            breaker.check(fake)

def test_threshold_breaker_reset():

    t = 5

    breaker = BL.models.ThresholdBreaker(
        threshold=t,
        exception_classes=[FakeError],
        reset_spec='2s')

    fake = FakeError('TestoReseto')
    for n in range(0, 5):
        breaker.check(fake)
    sleep(2.5)
    breaker.check(fake)
    with pytest.raises(BL.errors.BreakerTrippedError):
        for n in range(0, 5):
            breaker.check(fake)

def test_threshold_breaker_in_loop(setup):

    config, dbm = setup
    # Do brute force
    BL.brute.BruteForcer(config=config).launch()    

test_threshold_breaker_in_loop.CONFIG = dict(
        breakers=[BL.models.ThresholdBreaker(
            threshold=5,
            exception_classes=[FakeError])],
        authentication_callback=cb)

test_threshold_breaker_in_loop.DBM_CALLBACKS = dict(
    insert_username_records=dict(
        container=['u1', 'u2', 'u3'],
        associate_spray_values=False),
    insert_password_records=dict(
        container=['p1', 'p2', 'p3', 'p4', 'p5'],
        associate_spray_values=False),
    associate_spray_values=None)
