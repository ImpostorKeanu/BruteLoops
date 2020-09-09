import argparse

bp = brute_parser = argparse.ArgumentParser(add_help=False)

# ==================
# GENERAL PARAMETERS
# ==================

PARALLEL_GUESS_COUNT = \
'''
Number of processes to use during the attack, determinining the
count of parallel authentication attempts that are performed.
Default: %(default)s.
'''

AUTH_THRESHOLD = \
'''
Inclusive number of passwords to guess for a given username before
jittering for a time falling within the bounds of the values
specified for "Threshold Jitter". Default: %(default)s
'''

gg = general_group = bp.add_argument_group('General Parameters',
        'Options used to configure general attack parameters')
gg.add_argument('--parallel-guess-count','-pgc',
        type=int,
        default=1,
        help=PARALLEL_GUESS_COUNT)
gg.add_argument('--auth-threshold','-at',
        type=int,
        default=1,
        help=AUTH_THRESHOLD)

# =====================
# JITTER CONFIGURATIONS
# =====================

AUTH_JITTER_MINIMUM = \
'''
Minimum length of time to sleep between password guesses for
a given username. Default: %(default)s.
'''

AUTH_JITTER_MAXIMUM = \
'''
Maximum length of time to sleep between password guesses for
a given username. Default: %(default)s.
'''

THRESHOLD_JITTER_MINIMUM = \
'''
Minimum length of time to to wait before guessing anymore passwords
after meeting the authentication threshold for a given user, as
specified by the --auth-threshold argument. Default: %(default)s.
'''

THRESHOLD_JITTER_MAXIMUM = \
'''
Maximum length of time to to wait before guessing anymore passwords
after meeting the authentication threshold for a given user, as
specified by the --auth-threshold argument. Default: %(default)s.
'''

jg = jitter_group = bp.add_argument_group('Jitter Parameters',
        'Options used to configure jitter between authentication '\
        'attempts')
jg.add_argument('--auth-jitter-min','-ajmin',
        default='1s',
        help=AUTH_JITTER_MINIMUM)
jg.add_argument('--auth-jitter-max','-ajmax',
        default='1s',
        help=AUTH_JITTER_MAXIMUM)
jg.add_argument('--threshold-jitter-min','-tjmin',
        default='10m',
        help=THRESHOLD_JITTER_MINIMUM)
jg.add_argument('--threshold-jitter-max','-tjmax',
        default='30m',
        help=THRESHOLD_JITTER_MAXIMUM)

# =====================
# OUTPUT CONFIGURATIONS
# =====================

DB_FILE = \
'''
Name of the SQLite database file to store records associated
with the brute force attack. A new file will be created should
it not exist.
'''

LOG_FILE = \
'''
Name of the log file to store events stemming from the brute
force attack. Default: %(default)s. 
'''

LOG_STDOUT = \
'''
Issue this flag to disable printing log records to STDOUT along
with the log file. Default: %(default)s.
'''

og = output_group = bp.add_argument_group('Output Parameters',
        'Options related to output and logging targets')
og.add_argument('--db-file','-dbf',
        required=True,
        help=DB_FILE)
og.add_argument('--log-file','-lf',
        default='brute_log.txt',
        help=LOG_FILE)
og.add_argument('--log-stdout','-lso',
        action='store_false',
        help=LOG_STDOUT)

# ==============
# LOGGING LEVELS
# ==============

LOG_GENERAL = \
'''
Determine if general events should be logged to the sources
specified in "Output Parameters".
'''

LOG_VALID = \
'''
HIGHLY RECOMMENDED: Determine if valid credentials should
be logged to the sources specifid in "Output Parameters".
Default: %(default)s.
'''

LOG_INVALID = \
'''
Determine if invalid credentials should be logged to the
sources specifid in "Output Parameters". Useful for red
team engagements when the client wishes to have a precise
log of events. Default: %(default)s.
'''

lg = logging_group = bp.add_argument_group('Logging Parameters',
        'Options related to logging')
lg.add_argument('--log-general','-lg',
        action='store_false',
        help=LOG_GENERAL)
lg.add_argument('--log-valid','-lv',
        action='store_false',
        help=LOG_VALID)
lg.add_argument('--log-invalid','-liv',
        action='store_false',
        help=LOG_INVALID)
