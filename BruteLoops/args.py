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

STOP_ON_VALID = \
'''
Stop the brute force attack when valid credentials are recovered.
Default: %(default)s
'''

gg = general_group = bp.add_argument_group('General Parameters',
        'Options used to configure general attack parameters')
gg.add_argument('--parallel-guess-count','-pgc',
        type=int,
        default=1,
        help=PARALLEL_GUESS_COUNT,
        dest='process_count')
gg.add_argument('--auth-threshold','-at',
        type=int,
        default=1,
        help=AUTH_THRESHOLD,
        dest='max_auth_tries')
gg.add_argument('--stop-on-valid','-sov',
        action='store_true',
        help=STOP_ON_VALID)

# =====================
# JITTER CONFIGURATIONS
# =====================

JITTER_URL = 'https://github.com/arch4ngel/brute_loops/wiki/'

JITTER_DESCRIPTION = \
f'''
Options used to configure jitter between authentication attempts.
Expects each value expects a specially formatted value like their
defaults. Please see the "Jitter Time Format Specification" section
of the Wiki URL for more information on this format: {JITTER_URL}
'''

AUTH_JITTER_MINIMUM = \
'''
Minimum length of time to sleep between password guesses for
a given username. Default: %(default)s
'''

AUTH_JITTER_MAXIMUM = \
'''
Maximum length of time to sleep between password guesses for
a given username. Default: %(default)s
'''

THRESHOLD_JITTER_MINIMUM = \
'''
Minimum length of time to to wait before guessing anymore passwords
after meeting the authentication threshold for a given user, as
specified by the --auth-threshold argument. Default: %(default)s
'''

THRESHOLD_JITTER_MAXIMUM = \
'''
Maximum length of time to to wait before guessing anymore passwords
after meeting the authentication threshold for a given user, as
specified by the --auth-threshold argument. Default: %(default)s
'''

jg = jitter_group = bp.add_argument_group('Jitter Parameters',
        JITTER_DESCRIPTION)
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
force attack. Default: %(default)s 
'''

LOG_STDOUT = \
'''
Issue this flag to disable printing log records to STDOUT along
with the log file. Default: %(default)s
'''

og = output_group = bp.add_argument_group('Output Parameters',
        'Options related to output and logging targets')
og.add_argument('--db-file','-dbf',
        required=True,
        help=DB_FILE)
og.add_argument('--log-file','-lf',
        default='brute_log.txt',
        help=LOG_FILE)
og.add_argument('--no-log-stdout','-nlso',
        action='store_false',
        help=LOG_STDOUT)

# ==============
# LOGGING LEVELS
# ==============

LOG_GENERAL = \
'''
Disable logging of general events.
'''

LOG_VALID = \
'''
Disable logging of valid credentials. LIKELY UNDESIRABLE.
'''

LOG_INVALID = \
'''
Disable logging of invalid credentials.
'''

lg = logging_group = bp.add_argument_group('Logging Parameters',
        'Options related to logging')
lg.add_argument('--no-log-general','-nlg',
        action='store_false',
        help=LOG_GENERAL)
lg.add_argument('--no-log-valid','-nlv',
        action='store_false',
        help=LOG_VALID)
lg.add_argument('--no-log-invalid','-nliv',
        action='store_false',
        help=LOG_INVALID)

# ============
# INPUT PARSER
# ============

INPUT_DESCRIPTION = \
'''
Each of the following values is optional, though there must
be values in the SQLite database to target for attack. Also,
any combination of these values can be combined, as well.
'''

USERNAMES = \
'''
Space delimited list of username values to brute force.
'''

USERNAME_FILES = \
'''
Space delimited list of files containing newline separated
records of username values to brute force.
'''

PASSWORDS = \
'''
Space delimited list of password values to guess.
'''

PASSWORD_FILES = \
'''
Space delimited list of files containing newline separated
records of password values to guess.
'''

ip = input_parser = argparse.ArgumentParser(add_help=False)

ug = username_group = ip.add_argument_group('Username Configurations',
        'Username value and file parameters')
ug.add_argument('--usernames','-us',
        nargs='+',
        help=USERNAMES)
ug.add_argument('--username-files','-ufs',
        nargs='+',
        help=USERNAME_FILES)

pg = password_group = ip.add_argument_group('Password Configurations',
        'Password value and file parameters')
pg.add_argument('--passwords','-ps',
        nargs='+',
        help=PASSWORDS)
pg.add_argument('--password-files','-pfs',
        nargs='+',
        help=PASSWORD_FILES)

# =================
# CREDENTIAL PARSER
# =================

CREDENTIAL_DESCRIPTION = \
'''
Each of the following values is options, though
there must be values in the SQLited atabase to target for
attack. When used in a Spray attack, all passwords will
be used against all accounts during the brute force. When
used in a credential attack, only the matched records will
be attempted.
'''

CREDENTIALS = \
'''
Space delimited list of credential values to brute force.
'''

CREDENTIAL_FILES = \
'''
Space delimited list of files containing newline separated
CSV credential records to brute force.
'''

cp = credential_parser = argparse.ArgumentParser(add_help=False)

cg = credential_group = cp.add_argument_group(
        'Credential Configurations',
        'Credential record and credential file configurations.')

cg.add_argument('--credentials','-cs',
        nargs='+',
        help=CREDENTIALS)
cg.add_argument('--credential-files','-cfs',
        nargs='+',
        help=CREDENTIAL_FILES)
