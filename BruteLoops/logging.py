#!/usr/bin/env python3
import logging

VALID_CREDENTIALS   = 80
CREDENTIAL_EVENTS   = 70
GENERAL_EVENTS      = 60

LOG_FORMAT = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logging.addLevelName(VALID_CREDENTIALS,'VALID')
logging.addLevelName(CREDENTIAL_EVENTS,'INVALID')
logging.addLevelName(GENERAL_EVENTS,'GENERAL')
