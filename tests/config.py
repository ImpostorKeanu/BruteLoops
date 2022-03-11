import pytest
import bruteloops as BL
Config = BL.config.Config

def test_validate():

    config = Config()

    # Empty config
    with pytest.raises(ValueError):
        config.validate()

    # Bad process count
    with pytest.raises(ValueError):
        config.process_count = -1 
        config.validate()
    config.process_count = 1

    # Bad db_file
    with pytest.raises(ValueError):
        config.db_file = 86
        config.validate()
    config.db_file = 'junk'

    # =============
    # AUTH CALLBACK
    # =============

    class Test:
        pass

    with pytest.raises(ValueError):
        config.authentication_callback = Test()
        config.validate()

    # Bad auth callback
    Test.__call__ = lambda: None
    config.authentication_callback = Test()

    config.validate()

    # Bad exception handlers
    with pytest.raises(ValueError):
        config.exception_handlers = 'junk'
        config.validate()

    config.exception_handlers = {
            Exception:(lambda: True)}
    config.validate()

