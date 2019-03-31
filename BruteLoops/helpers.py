#!/usr/bin/env python3

def strip_newline(s):
    '''
    Strips the final character from a string via list comprehension. Useful when
    ```str.strip()``` might pull a legitimate whitespace character from a password.
    '''

    if s[-1] == '\n':

        return s[:len(s)-1]

    else:

        return s
