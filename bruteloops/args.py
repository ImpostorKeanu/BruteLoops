import argparse
from zoneinfo import ZoneInfo
from time import strptime

class BoolAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):

        setattr(namespace, self.dest, False)
        if values in ['true','True']:
            setattr(namespace, self.dest, True)

class TimezoneAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):

        try:

            values = ZoneInfo(values)

        except Exception:

            raise ValueError(
                'Invalid timezone value supplied. See the '
                '"TZ database name" column of the following resource '
                'for valid values: '
                'https://en.wikipedia.org/wiki/List_of_tz_database_ti'
                'me_zones')

        setattr(namespace, self.dest, values)

class BlackoutAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):

        values = values.split('-')

        if not len(values) == 2:

            raise ValueError(
                f'Invalid format used for blackout window: {values}. '
                'It must be a hyphen delimited pair of time ranges in '
                'H:M:S format.'
            )

        start = strptime(values[0], '%H:%M:%S')
        stop  = strptime(values[1], '%H:%M:%S')

        setattr(namespace, 'blackout_start', start)
        setattr(namespace, 'blackout_stop', stop)

# ==================
# GENERAL PARAMETERS
# ==================

PARALLEL_GUESS_COUNT = \
'''Number of processes to use during the attack, determinining the
count of parallel authentication attempts that are performed.
Default: %(default)s.
'''

AUTH_THRESHOLD = \
'''Inclusive number of passwords to guess for a given username before
jittering for a time falling within the bounds of the values
specified for "Threshold Jitter". Default: %(default)s
'''

STOP_ON_VALID = \
'''Stop the brute force attack when valid credentials are recovered.
'''

PRIORITY_USERNAMES = \
'''Usernames to prioritize over all others when guessing, moving
them to the front of the guess queue.
'''

PRIORITY_PASSWORDS = \
'''Passwords to prioritize over all others when guessing, moving
them to the front of the guess queue.
'''

BLACKOUT_WINDOW = (
'Window of time where no additional guesses should be performed at '
'all. Useful in situation where attacks are to be restricted to '
'specific testing windows. The range format should be two time values '
'"H:M:S" separated by a hyphen ("-") character. Hours should be '
'provided in 24-hour format, eg 13 for 1PM. Example: '
'17:00:00-09:00:00')

gp = general_parser = argparse.ArgumentParser(add_help=False)
gg = general_group = gp.add_argument_group('General Parameters',
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
    action=argparse.BooleanOptionalAction,
    default=False,
    help=STOP_ON_VALID)
gg.add_argument('--blackout-window', '-bw',
    required=False,
    action=BlackoutAction,
    help=BLACKOUT_WINDOW)

# ===============
# TIMEZONE PARSER
# ===============

TIMEZONE = \
'''Timezone used while deriving timestamps. Be sure to use a
consistent value for this configuration across restarts, otherwise
lockouts may occur. See the "TZ database name" column in this 
resource for valid values: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones 
. (Required: %(required)s)
'''

timezone_parser = tz_p = argparse.ArgumentParser(add_help=False)
tz_p.add_argument('--timezone','-tz',
    action=TimezoneAction,
    required=False,
    help=TIMEZONE)

# ===============================
# SCHEDULING TWEAK CONFIGURATIONS
# ===============================

stp = scheduling_tweaks_parser = argparse.ArgumentParser(
    add_help=False)
stg = scheduling_tweaks_group = stp.add_argument_group(
    'Scheduling Tweak Parameters',
    'Options used to prioritize username or password values')
stg.add_argument('--prioritize',
    action=argparse.BooleanOptionalAction,
    default=True,
    help='Determine if values should be prioritized or '
        'unprioritized. Default: %(default)s')
stg.add_argument('--usernames',
    nargs='+',
    help='Usernames to manage')
stg.add_argument('--passwords',
    nargs='+',
    help='Passwords to manage')

# =====================
# JITTER CONFIGURATIONS
# =====================

JITTER_URL = 'https://github.com/arch4ngel/brute_loops/wiki/'

JITTER_DESCRIPTION = \
f'''Options used to configure jitter between authentication attempts.
Expects each value expects a specially formatted value like their
defaults. Please see the "Jitter Time Format Specification" section
of the Wiki URL for more information on this format: {JITTER_URL}
'''

AUTH_JITTER_MINIMUM = \
'''Minimum length of time to sleep between password guesses for
a given username. Default: %(default)s
'''

AUTH_JITTER_MAXIMUM = \
'''Maximum length of time to sleep between password guesses for
a given username. Default: %(default)s
'''

THRESHOLD_JITTER_MINIMUM = \
'''Minimum length of time to to wait before guessing anymore passwords
after meeting the authentication threshold for a given user, as
specified by the --auth-threshold argument. Default: %(default)s
'''

THRESHOLD_JITTER_MAXIMUM = \
'''Maximum length of time to to wait before guessing anymore passwords
after meeting the authentication threshold for a given user, as
specified by the --auth-threshold argument. Default: %(default)s
'''

jp = jitter_parser = argparse.ArgumentParser(add_help=False)
jg = jitter_group = jp.add_argument_group('Jitter Parameters',
        JITTER_DESCRIPTION)
jg.add_argument('--auth-jitter-min','-ajmin',
        default='1s',
        help=AUTH_JITTER_MINIMUM)
jg.add_argument('--auth-jitter-max','-ajmax',
        default='1s',
        help=AUTH_JITTER_MAXIMUM)
jg.add_argument('--threshold-jitter-min','-tjmin',
        default='1.5h',
        help=THRESHOLD_JITTER_MINIMUM)
jg.add_argument('--threshold-jitter-max','-tjmax',
        default='2.5h',
        help=THRESHOLD_JITTER_MAXIMUM)

# =====================
# OUTPUT CONFIGURATIONS
# =====================

LOG_FILE = \
'''Name of the log file to store events stemming from the brute
force attack. Default: %(default)s 
'''

LOG_STDOUT = \
'''Enable/disable logging to stdout.
'''

LOG_LEVEL = \
'''Determines the logging level. Default: %(default)s
'''

op = output_parser = argparse.ArgumentParser(add_help=False)
og = output_group = op.add_argument_group('Output Parameters',
        'Options related to output and logging targets')
og.add_argument('--log-file','-lf',
        default='brute_log.txt',
        help=LOG_FILE)
og.add_argument('--log-stdout',
        action=argparse.BooleanOptionalAction,
        default=True,
        help=LOG_STDOUT,
        dest='log_stdout')
og.add_argument('--log-level',
        choices=('general',
            'valid-credentials',
            'invalid-credentials',
            'invalid-usernames'),
        default='valid-credentials',
        help=LOG_LEVEL)       

# ==============
# LOGGING LEVELS
# ==============

#LOG_GENERAL = \
#'''Manage logging of general events. Default: %(default)s
#'''
#
#LOG_VALID = \
#'''Manage logging of valid credentials. Default: %(default)s.
#'''
#
#LOG_INVALID = \
#'''Manage logging of invalid credentials. Default: %(default)s
#'''
#
#LOG_INVALID_USERNAME = \
#'''Manage logging of invalid usernames. Default: %(default)s
#'''
#
#lp = logging_parser = argparse.ArgumentParser(add_help=False)
#lg = logging_group = lp.add_argument_group('Logging Parameters',
#        'Options related to logging')
#
#lg.add_argument('--log-general',
#        action=argparse.BooleanOptionalAction,
#        default=True,
#        help=LOG_GENERAL,
#        dest='log_general')
#lg.add_argument('--log-valid',
#        action=argparse.BooleanOptionalAction,
#        default=True,
#        help=LOG_VALID,
#        dest='log_valid')
#lg.add_argument('--log-invalid',
#        action=argparse.BooleanOptionalAction,
#        default=True,
#        help=LOG_INVALID,
#        dest='log_invalid')
#lg.add_argument('--log-invalid-usernames',
#        action=argparse.BooleanOptionalAction,
#        default=True,
#        help=LOG_INVALID_USERNAME,
#        dest='log_invalid_usernames')


# ============
# INPUT PARSER
# ============

INPUT_DESCRIPTION = \
'''Each of the following values is optional, though there must
be values in the SQLite database to target for attack. Also,
any combination of these values can be combined, as well.
'''

USERNAMES = \
'''Space delimited list of username values to brute force.
'''

USERNAME_FILES = \
'''Space delimited list of files containing newline separated
records of username values to brute force.
'''

PASSWORDS = \
'''Space delimited list of password values to guess.
'''

PASSWORD_FILES = \
'''Space delimited list of files containing newline separated
records of password values to guess.
'''

PRIORITIZE_VALUES = \
'''Mark values as priority in the database.
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
'''Each of the following values is options, though
there must be values in the SQLited atabase to target for
attack. When used in a Spray attack, all passwords will
be used against all accounts during the brute force. When
used in a credential attack, only the matched records will
be attempted.
'''

CREDENTIALS = \
'''Space delimited list of credential values to brute force.
'''

CREDENTIAL_FILES = \
'''Space delimited list of files containing newline separated
: credential records to brute force.
'''

AS_CREDENTIALS = \
'''Flag determining if the input values should be treated as
credential records in the database, not as spray values. This
means that only a single guess will be made using this password
and it will target the supplied username.
'''

CREDENTIAL_DELIMITER = \
'''The character value that delimits the username and password values
of a given credential, for instance ":" would be the proper delimiter
for a given credential "administrator:password123". NOTE: The value of
this field has no affect on the "--csv-files" flag. Default: ":"
'''

CSV_FILES = \
'''Treat the input files as CSV format. Unlike the "--credential-files"
option, this technique uses Python's standard CSV library to parse out
the header file and import the target lines. Note that the "--credenti
al-delimiter" flag has no affect on these inputs.
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
cg.add_argument('--credential-delimiter',
        default=':',
        help=CREDENTIAL_DELIMITER)
cg.add_argument('--csv-files',
        nargs='+',
        help=CSV_FILES)

#bp = brute_parser = argparse.ArgumentParser(parents=[gp,jp,op,lp,ip,cp])
bp = brute_parser = argparse.ArgumentParser(parents=[gp,jp,op,ip,cp])
