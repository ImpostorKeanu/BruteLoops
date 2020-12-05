#!/usr/bin/env python3
import logging

SLEEP_EVENTS            = 85
VALID_CREDENTIALS       = 80
CREDENTIAL_EVENTS       = 70
GENERAL_EVENTS          = 60

FORMAT='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FORMAT = logging.Formatter(FORMAT)

logging.addLevelName(SLEEP_EVENTS,'SLEEP_EVENT')
logging.addLevelName(VALID_CREDENTIALS,'VALID')
logging.addLevelName(CREDENTIAL_EVENTS,'INVALID')
logging.addLevelName(GENERAL_EVENTS,'GENERAL')
