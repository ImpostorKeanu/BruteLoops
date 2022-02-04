# Variables containing data values from the datasets directory. To
# avoid unneccessarily loading the datasets, loader functions are
# made available. Call loader functions to populate the variables.

from pathlib import Path
from logging import getLogger

log = getLogger('BruteLoops.data')

USER_AGENT_STRINGS = UAS = []

def loadUserAgents(path:str=None, force=False) -> None:
    '''Load user agent strings from the datasets directory into
    the USER_AGENT_STRINGS module variable.

    Args:
        path: Full path to the file that should be imported. If None,
            the default, then the datasets directory will be derived
            from the module path and the file "ua_strings.txt" will
            be loaded.

    Raises:
        FileNotFound error when an invalid path is supplied.
    '''

    if UAS and not force:
        return

    path = path if path else Path(__file__).parent / 'datasets/ua_strings.txt'


    if not path.exists():

        log.log(60, f'Fatal: User agent string source missing!')

        raise FileNotFoundError(
            'Source for user agent strings source was not found: ' +
            str(path))

    with path.open() as infile:

        c = 0
        for l in infile:
            l = l.strip()
            if not l in UAS:
                c += 1
                UAS.append(l)
