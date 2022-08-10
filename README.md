# BruteLoops

A dead simple library providing the foundational logic for
efficient password brute force attacks against authentication
interfaces.

# Documentation

Documentation can be found [*here*](https://arch4ngel.github.io/BruteLoops/).

# If you're looking for the old example modules...

See [BFG](https://github.com/arch4ngel/bl-bfg).

The examples have been offloaded to a distinct project to
minimize code and packaging issues. Database and attack
capabilities have also been merged into a single binary.

# Key Features

- **Protocol agnostic** - If a callback can be written in Python,
BruteLoops can be used to attack it
- **SQLite support** - All usernames, passwords, and credentials
are maintained in an SQLite database.
  - A companion utility (`dbmanager.py`) that creates and manages
  input databases accompanies BruteLoops
- **Spray and Stuffing Attacks in One Tool** - BruteLoops supports both
spray and stuffing attacks in the same attack logic and database, meaning
that you can configure a single database and run the attack without heavy
reconfiguration and confusion.
- **Guess scheduling** - Each username in the SQLite database is configured
  with a timestamp that is updated after each authentication event. This
  means we can significantly reduce likelihood of locking accounts by
  scheduling each authentication event with precision.
- **Fine-grained configurability to avoid lockout events** - Microsoft's
lockout policies can be matched 1-to-1 using BruteLoop's parameters:
  - `auth_threshold` = Lockout Threshold
  - `max_auth_jitter` = Lockout Observation Window
  - Timestampes associated with each authentication event are tracked
  in BruteLoops' SQLite database. Each username receives a distinct
  timestamp to assure that authentication events are highly controlled.
- **Attack resumption** - Stopping and resuming an attack is possible
  without worrying about losing your place in the attack or locking accounts.
- **Multiprocessing** - Speed up attacks using multiprocessing! By configuring
  the parallel guess count, you're effectively telling BruteLoops how many
  usernames to guess in parallel.
- **Logging** - Each authentication event can optionally logged to disk.
  This information can be useful during red teams by providing customers
  with a detailed attack timeline that can be mapped back to logged events.
- **Breakers** - Breakers behave like circuit breakers. An exception can
  be raised *x* number of times before ending the attack loop. They can
  reset after a given period of time as well, allowing for configurations
  like "Exit after 6 ConnectionErrors occur".

# Dependencies

BruteLoops requires __Python3.7 or newer__ and
[SQLAlchemy 1.3.0](https://www.sqlalchemy.org/), the latter of
which can be obtained via pip and the requirements.txt file in
this repository: `python3.7 -m pip install -r requirements.txt`

# Installation

```
git clone https://github.com/arch4ngel/bruteloops
cd bruteloops
python3 -m pip install -r requirements.txt
```
