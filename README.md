# BruteLoops

A dead simple library to support protocol agnostic horizontal brute force attacks targeting authentication interfaces by providing functions that handle efficient looping and timing logic. Logic involving authentication, such as making an HTTP request and analyzing the response, is left up to the program utilizing the library - thus providing a consistent and dependable platform to craft brute force attacks targeting new protocols and applications.

__See the [example](https://github.com/arch4ngel/brute_loops/wiki/A-Brief-Example) page in the wiki for a brief walkthrough.__

# Dependencies

BruteLoops requires __Python3.7 or newer__ and [SQLAlchemy 1.3.0](https://www.sqlalchemy.org/), the latter of which can be obtained via pip and the requirements.txt file in this repository: `python3.7 -m pip install -r requirements.txt`

# Features

- Protocol Agnostic - So long as a Python function or callable object can be written for a target protocol, this library provides the basic looping logic.
- Though usernames and passwords are supplied via input files and/or lists, an SQLite database is used to support all brute force attacks, allowing BruteLoops to use SQL while selecting usernames to target during attack execution
- Multiprocessing Support
- Timing Configuration (optionial) - BruteLoops currently provides two timing configurations to avoid locking user accounts:
  - `authentication_jitter` - A range of time a given process will sleep between authentication attempts
  - `max_auth_jitter` - A range of time that must pass before attempting to authenticate a given username again
- Logging (optional) - Log to a file, stderr, or stdout (or multiple) using a standard format. Logging is also __optional__, i.e. the developer can log successful authentication in the callback itself if desired.
- Attack Resumption - Inputs (usernames/passwords) are parsed and imported into a SQLite database, where each username has a `last_password_id` indicating the last password guessed. Assuming integrity of the database is maintained between attacks, this allows for attacks to resume where last interrupted.
- Efficient execution (see [Efficient Algorithm](https://github.com/arch4ngel/brute_loops/wiki/The-BruteLoops-Approach-to-a-Horizontal-Brute-Force-Attack]))

# TODO:

- Handle blank username/password values
    - Potentially a decorator added to the callable that replaces strings with a string literal of `''` should they match a specific pattern?
    - May be easier to update the DB schema to accept a Null value which translates to a `''`
- Handle multiple hosts for a given credential
    - Should probably be handled at the callback....?
