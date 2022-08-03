from enum import Enum, IntEnum

class LogLevelEnum(Enum):
    'Map friendly names to logging levels.'

    INVALID_USERNAME = 'invalid-usernames'
    ('Most verbose level of logging that sends events related to '
     'invalid usernames')

    #SLEEP_EVENTS = 'sleep_states'
    #'Logs when no sleep times over 60 seconds are scheduled to occur.'

    VALID_CREDENTIALS = 'valid-credentials'
    'Log valid credentials.'

    CREDENTIAL_EVENTS = 'invalid-credentials'
    'Log invalid credential guesses.'

    GENERAL_EVENTS = 'general'
    'Log general events, i.e. when an attack starts and stops.'

class GuessOutcome(IntEnum):
    'Map guess outcome sto friendly names.'

    failed  = -1
    'Failed to guess credentials.'

    invalid = 0
    'Invalid credentials.'

    valid   = 1
    'Valid credentials.'

