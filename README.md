# BruteLoops

A dead simple library to support protocol agnostic horizontal brute force attacks targeting authentication interfaces, commonly referred to as 'credential stuffing', by providing functions that handle efficient looping and timing logic. Logic involving authentication, such as making an HTTP request and analyzing the response, is left up to the program utilizing the library - thus providing a consistent and dependable platform to craft brute force attacks targeting new protocols and applications.

__See the [example](https://github.com/arch4ngel/brute_loops/wiki/A-Brief-Example) page in the wiki for a brief walkthrough.__

# Features

- Protocol Agnostic - So long as a Python function or callable object can be written for a target protocol, this library provides the basic looping logic.
- Multiprocessing Support
- Timing Configuration - BruteLoops currently provides two timing configurations to avoid locking user accounts:
  - `authentication_jitter` - A range of time a given process will sleep between authentication attempts
  - `max_auth_jitter` - A range of time that must pass before attempting to authenticate a given username again
- Logging (optional) - Log to a file, stderr, or stdout (or multiple) using a standard format. Logging is also __optional__, i.e. the developer can log successful authentication in the callback itself if desired.
- Attack Resumption - Inputs (usernames/passwords) are parsed and imported into a SQLite database, where each username has a `last_password_id` indicating the last password guessed. Assuming integrity of the database is maintained between attacks, this allows for attacks to resume where last interrupted.
- Highly efficient execution (see [Efficient Algorithm](#Efficient-Algorithm))

# Efficient Algorithm

Standard horizontal brute force techniques commonly rely on simple loops, imposing two significant inefficiencies when confronted with lockout policies:

## Inefficient Sleep Times

A period of time is typically configured to pass between authentication attempts to avoid locking out accounts. If a standard loop is being used, this means a sleep period will occur only after all target usernames have been guessed. Given a large number of usernames and a minimum of several seconds per authentication, a significant period of time may have passed between the first authentication attempt and the last.

For example: Let's say that we have a list of 1,000 usernames to target for authentication and each transaction takes approximately 5 seconds to complete. Between the first auth transaction targeting username1 and the final auth transaction targeting username1000, approximately ~83 minutes will have passed (`999*5/60=83.25`). Assuming a sleep time of one hour between authentication attempts, username1 will have gone ~143 (`999*5/60+60=143.25`) minutes without being targeted for authentication instead of 60.

Wouldn't it be more efficient to select usernames to target based on timestamp instead of general ordering?

## Password Chunking

Standard horizontal brute force mechanisms attempt a single password for each username, which is inefficient because current lockout policies typically allow up to three attempts before disabling an account.

Wouldn't it be more efficient to select a chunk of passwords to guess during a single authentication window?

## Mitigating the Inefficiencies

BruteLoops uses a SQLite database to track usernames and passwords used during execution, bypassing the restriction of the standard looping approach and allowing for flexible selection of target values based on the time which the last authentication attempt for a given username occurred. Based on the user-supplied configuration, BruteLoops calculates a value (`future_time`) determining the next time a given username can be targeted for authentication. While potential username and password combinations are available, BruteLoops will loop and use SQL to select usernames with a `future_time` value that is less than or equal to the current time and proceed to target them for password guessing.

Password chunking is achieved by calculating a password offset based on the `max_auth_tries` configuration and the `id` value of password records: `SELECT * FROM passwords OFFSET Username.last_password_id LIMIT (Username.last_password_id+max_auth_tries)`. Should a `max_auth_tries` configuration be set to 3, for example, a total of three passwords will be pulled from the databased guessed for a given user per authentication window.
