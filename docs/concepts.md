BruteLoops abstracts common logic found in password guessing
utilties and implements it in a library, allowing it to be reused
it in any Linux Python application.

The following flowchart illustrates the classes and methods involved
with generating a database and initiating an attack.

- The [`bruteloops.db_manager.Manager`](/pkg-docs/db_manager/#bruteloops.db_manager.Manager)
  class provides comprehensive methods to create a database and
  manage authentication data,
  i.e. usernames and passwords.
- The [`bruteloops.brute.BruteForcer`](/pkg-docs/brute/#bruteloops.brute.BruteForcer)
  class provides the `launch` method that initiates a perpetual
  control loop that orchestrates credentials guesses until all
  values are exhausted.

``````mermaid
flowchart
db-manager("bruteloops.db_manager.Manager")
db-file("SQLite File")
brute-forcer("bruteloops.brute.BruteForcer.launch()")
control-loop((("Control
    Loop")))
db-manager -->|Creates/Populates| db-file
brute-forcer -->|Starts| control-loop
control-loop -->|Reads/Updates| db-file

loop-note("
    Orchestrates and guesses
    credentials")
loop-note -..-> control-loop
``````

Remaining sections of this document provide a high-level overview
of key concepts implementers will need to understand to implement
the API effectively.

### Control Loop

The control loop is responsible for orchestrating authentication
guesses. It queries the SQLite database for credentials that can
be guessed and sends them to an application-defined authentication
callback for guessing. It's engaged by instantiating a
[`bruteloops.brute.BruteForcer`](/pkg-docs/brute/#bruteloops.brute.BruteForcer)
instance with a
[`bruteloops.models.Config`](/pkg-docs/models/#bruteloops.models.Config)
object and calling the `brute()` method.

The diagram below illustrates high-level logic of the control loop
during execution.

``````mermaid
flowchart

target("Target Auth. Interface")

wait-for-guessable-creds("Wait for guessable creds")
get-guessable-creds("Query guessable creds")
get-guessable-creds -->|"Update
    timestamps"| record-outcome
guess-creds("Guess actionable creds")
auth-callback("Execute Auth. Callback")
record-outcome("Update DB")
except{"
    Exceptions
    raised?"}
record-outcome --> except
exit-loop("Exit Control Loop")
except -->|Yes| breakers

subgraph except-handling["Exception Handling"]
    breakers("Breakers")
    standard-handlers("Standard Handlers")
    breakers --> breaker-trip
    breaker-trip{"Breaker
        tripped?"}
    breaker-trip -->|No| standard-handlers
end

except -->|No| attack-finished
attack-finished{"Attack
    finished?"}
attack-finished -->|Yes| exit-loop
attack-finished -->|No| wait-for-guessable-creds
breaker-trip -->|Yes| exit-loop
    
auth-callback -->|Hits| target


wait-for-guessable-creds --> get-guessable-creds --> guess-creds
guess-creds --->|"
    Send to
    callback"| auth-callback
auth-callback --->|"
    Returns
    outcome"| guess-creds
guess-creds --->|"Update cred to
    valid/invalid"| record-outcome
``````

### Authentication Callback

The authentication callback is a function defined by the implementing
application. It's passed to the control loop at runtime. The code block
below outlines the required function signature for authentication callbacks:

``````python
def my_auth_callback(username:str password:str) -> dict:
    '''Contrived callback to illustrate function signature.

    Args:
      username: String username to guess.
      password: String password to guess.

    Returns:
      Dictionary value conforming to `bruteloops.model.Output`
    '''

    # Must return a dictionary
    out = dict(outcome=0)

    # ...guess the credential...
    if guess.valid: out['outcome'] = 1

    return out
``````

Return value and arguments aside, there are no limitations applied to this
function. The implementing application can be as creative as it needs to bo
to guess a given credential.

### Data Management

As mentioned previously, all data is stored and maintained in an SQLite database.
BruteLoops provides classes and methods to support database interaction. See the
following for additional information on this:

- [Database Management Reference](/reference/db_management/) for examples of support
  components.
- [SQL Documentation](/pkg-docs/sql) for the database schema.

### Breakers

Breakers behave like circuit breakers, providing a safety capability that will
terminate an attack when undesirable conditions are observed. This capability is
provided to avoid sweeping lockout events and denial of service conditions. See
the following for more information on breakers:

- [Reference Documentation](/reference/breakers)
- Relevant models:
    - [`bruteloops.models.Breaker`](/pkg-docs/models/#bruteloops.models.Breaker)
    - [`bruteloops.models.ThresholdBreaker`](/pkg-docs/models/#bruteloops.models.ThresholdBreaker)
