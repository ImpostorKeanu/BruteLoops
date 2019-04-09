#!/usr/bin/env python3

from BruteLoops.jitter import Jitter
from BruteLoops.brute import Horizontal
from BruteLoops.config import Config
from BruteLoops.logging import GENERAL_EVENTS,logging
from BruteLoops.examples import handles

import cmd, sys
from types import MethodType
from suffix_printer import *

class Interface(cmd.Cmd):
    intro = '[Initializing Example Harness 0.01]'
    prompt = '[BruteLoops]> '

    def __init__(self, *args, **kwargs):
        self.module = None
        self._module = None
        self.attacks = {}
        super().__init__(*args,**kwargs)

    def do_show(self,target):

        if target == 'modules':
            print('\n'+'\n'.join(handles.keys())+'\n')
        elif target == 'jobs':
            print('SHOWING JOBS')
        elif target == 'options':
            if not self.module: 
                print('NO MODULE SELECTED')
                return
            print()
            for k,v in self._module.config.__dict__.items():
                if v.__class__ == MethodType: continue
                print(f'{k}: {v}')


    def do_use(self,target):

        if target in handles:
            self.module = target
            self._module = handles[target]
            self._module.__setattr__('config',Config())
            self.prompt=f'[BruteLoops][{target}]> '

    def do_exit(self,args):
        sprint('Exiting')
        sys.exit()

if __name__ == '__main__':
    Interface().cmdloop()
