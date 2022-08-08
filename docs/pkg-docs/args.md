# Pre-Defined Argparse Arguments

BruteLoops provides pre-defined [`argparse.ArgumentParser`](https://docs.python.org/3/library/argparse.html#argumentparser-objects) 
objects that can be dropped directly into applications.

## Example Usage

This example is naive. It illustrates only how to incorporate a random
set of arguments into an application.

``````python
import bruteloops as BL
import argparse

parser = argparse.ArgumentParser(
    prog='My Program',
    description='This is my program\'s description.',
    parents=[BL.args.brute_parser])
``````

---

::: bruteloops.args
