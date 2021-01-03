#!/usr/bin/env python3

import BruteLoops
from BruteLoops.jitter import Jitter
from BruteLoops.brute import BruteForcer
from BruteLoops.config import Config
from BruteLoops import logging
from BruteLoops.logging import getLogger, GENERAL_EVENTS
from BruteLoops.example import parser
import traceback
import argparse

# ========================
# USER INTERFACE SHORTCUTS
# ========================
# Primarily to handle KeyboardInterrupts.

def get_user_input(m):
    '''
    Simple input loop expecting either a ```y``` or ```n``` response.
    '''

    uinput = None
    while uinput != 'y' and uinput != 'n':
        uinput = input(m)

    return uinput

def handle_keyboard_interrupt(brute,exception):

    print()
    print('CTRL+C Captured\n')
    resp = get_user_input('Kill brute force?(y/n): ')

    if resp == 'y':
        print('Kill request received')
        print('Monitoring final processes completion')
        bf.shutdown()
        print('Exiting')
        exit()
    else:
        return 1

if __name__ == '__main__':

    # Parse the arguments
    args = parser.parse_args()

    # Initialize a BruteLoops.config.Config object
    config = Config()

    # Initialize the callback from the module bound to the argument
    # parser when the interface was being built
    config.authentication_callback = args.module.initialize(args)

    # Authentication Configurations
    config.process_count = args.process_count
    config.max_auth_tries = args.max_auth_tries
    config.stop_on_valid = args.stop_on_valid

    # Jitter Configurations
    config.authentication_jitter = Jitter(min=args.auth_jitter_min,
            max=args.auth_jitter_max)
    config.max_auth_jitter = Jitter(min=args.threshold_jitter_min,
            max=args.threshold_jitter_max)

    # Output Configurations
    config.db_file = args.dbfile

    # Log destinations
    config.log_file = args.log_file
    config.log_stdout = args.log_stdout

    # Log Levels
    config.log_general = args.log_general
    config.log_valid = args.log_valid
    config.log_invalid = args.log_invalid

    # Configure an exception handler for keyboard interrupts    
    config.exception_handlers={KeyboardInterrupt:handle_keyboard_interrupt}
    
    # Always validate the configuration.
    config.validate()
   
    # Configure logging
    logger = getLogger('example.py',log_level=10)
    
    try:
    
        logger.log(GENERAL_EVENTS,'Initializing attack')
        bf = BruteForcer(config)
        bf.launch()
        logger.log(GENERAL_EVENTS,'Attack complete')
        
    except Exception as e:
    
        print()
        print('Unhandled exception occurred.\n')
        print(e)
        print(e.with_traceback(e.__traceback__))
        print(e.__traceback__.__dir__())
        print(e.__traceback__.tb_lineno)
        traceback.print_tb(e.__traceback__)
        print()
        print()
