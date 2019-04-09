#!/usr/bin/env python3

from . import owa2016
from . import adfs
from . import fake

from .owa2016 import *
from .adfs import *
from .fake import *

from pathlib import Path

from sys import modules,exit
from pathlib import Path
from importlib.util import spec_from_file_location,module_from_spec
import inspect
from re import match

# =====================================
# GET THE PATH TO THE MODULES DIRECTORY
# =====================================
m = match(r'/.+/',inspect.getfile(
        inspect.currentframe()
    )
)

# ========================
# DYNAMICALLY LOAD MODULES
# ========================

# Catch each module in a dictionary to be read by the main program
handles = {}

base = m.string[m.start():m.end()]

# Sort the file names to organize the modules by name at the main interface
files = sorted(
    [
        f.name for f in Path(base).glob('**/*.py')
        if not f.name.startswith('_')
    ]
)

for f in files:

    mname = f[:len(f)-3]

    # https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path
    # This is pretty much magic to me
    spec = spec_from_file_location(mname, base+f)
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    handles[mname] = mod
