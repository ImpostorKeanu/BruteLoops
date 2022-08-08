# Time Variation via Jitter

A jitter configuration specifies an upper and lower time boundary,
i.e. a `min` and a `max`. BruteLoops uses jitter values and timestamps
stored in the SQLite database to make timing decisions during attack
exeuction, e.g. "do not guess this username untl this time" and/or
"wait *x* seconds before guessing the next password".

## Two Jitter Points

BruteLoops can apply jitter at two points in a BruteForce attack:

1. **Authentication** (`Config.authentication_jitter`) - Time slept after
    guessing a credential.
    - `time.sleep(auth_jitter)` is applied in child process that performed
      the guess.
    - Exists primarily for detection avoidance.
2. **Max Auth** (`Config.max_auth_jitter`) - Time waited after a maximum
    number of guesses for a username has been made.
    - Exists primarily to mitigate account lockouts.
    - Derived from a "future timestamp" taken after the most recent guess
      for a username.
    - SQL queries select usernames where `future_time <= current_time`

The following diagram roughly illustrates where these jitter
configurations are applied during an attack:

``````mermaid
flowchart

only-creds("Returns creds with
    future timestamp <= current time") -..-> get-guessable-creds

calc-note("Calculated from
    'max auth jitter'
    setting")

calc-note -..-> update-username-timestamp

subgraph sg-control-loop["Control Loop"]

    get-guessable-creds("Get actionable creds")
    guess-creds(Guess returned creds)

    get-guessable-creds -->|"Returns
        credentials"| guess-creds

    guess-creds -->|"Each cred guessed
        in a subprocess"| sp1

    subgraph sg-subprocs["Subprocesses"]
        sp1(["Process 1"])
    end

    update-username-timestamp("Apply updated
        future timestamp")
    guess-creds --> update-username-timestamp
    update-username-timestamp -->|"Get next
        actionable creds"| get-guessable-creds

    subgraph sg-acb["Authentication Callback"]
        exec-callback("Execute Callback")
        sp1 -->|"Guess
            credential"| exec-callback
    
        auth-jitter[\"Apply Auth Jitter
            (sleep)"\]
        exec-callback -->|"Do jitter"| auth-jitter
        auth-jitter -->|"Return
            output"| sp1
    end
    
    sp1 -->|"Return
        output"| guess-creds
end
``````

## How are Jitter Configurations Supplied to `BruteForcer.launch()`?

Jitter configurations are accepted from the user via interface created
by the implementing application and passed to
[`bruteloops.models.Config`](/pkg-docs/models/#bruteloops.models.Config) for
validation. The `Config` object is then passed to
[`bruteloops.brute.BruteForcer`](/reference/attack_management) to initiate
a brute force attack.

``````mermaid
flowchart

uinput(User Input)
config-model(bruteloops.models.Config)
brute-forcer(bruteloops.brute.BruteForcer.__init__)
do-attack("bruteloops.brute.BruteForcer.launch()")

uinput -->|Passed to| config-model
config-model -->|Used to instantiate| brute-forcer
brute-forcer -->|Launch attack| do-attack
``````

!!! warning

    [`bruteloops.jitter.JitterTime`](#bruteloops.jitter.JitterTime)
    was the original implementation and will be removed once all references
    have been purged.

Jitter inputs are supplied via the following configrations
made accessible from the [`bruteloops.models.Config` model](/pkg-docs/models/#bruteloops.models.Config):

- `authentication_jitter`
- `max_auth_jitter`

## Format Specification

The `min` and `max` arguments passed to [`bruteloops.models.Jitter` model](#bruteloops.models.Jitter)
each expect string values formatted to the following specification.

### Jitter String Format

The format translates to, where duriation is either
a float or integer and time unit is a single character.

`<duration>*<time-unit>`

### Supported Time Units

- `s` - Second(s)
- `m` - Minute(s)
- `h` - Hour(s)
- `d` - Day(s)

### Examples

#### Formatted Values

- `10m` - 10 minutes
- `2h` - 2 hours
- `1.5` - 1 hour and 30 minutes

#### Configuration Example

The following example creates a `bruteloops.models.Config` with jitter
values for:

- Try up to 3 passwords for a username.
- Sleep between 10 seconds and 1 minute between guesses.
- Make no additional guesses for that user until after at least 31
  minutes pass.

``````python
import bruteloops
config = bruteloops.models.Config(
    db_file='/tmp/test.db',
    max_auth_tries=3,
    authentication_jitter=dict(min='10s', max='1m'),
    max_auth_jitter=dict(min='31m', max='1h'),
    authentication_callback=lambda username, password: True)
``````

---

::: bruteloops.models.Jitter

---

::: bruteloops.jitter.JitterTime

---
