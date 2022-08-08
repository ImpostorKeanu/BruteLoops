BruteLoops provides a [BruteForcer](#bruteloops.brute.BruteForcer) class
to streamline brute force attacks. All looping, timing, and control logic
is defined in [brute](#bruteloops.brute.BruteForcer.launch).

## Examples

!!! note

    See [Complete Attack Examples](/complete_examples) for start-to-finish
    examples.

### Basic Attack Configuration

First, you'll need to create a [`Config`](/pkg-docs/models#bruteloops.models.Config) object
with all the values needed to manage the attack.

``````python
def auth_func(username, password):
    # This authenticates the credentials
    # ...guess the username and password...
    out = dict(outcome=0, username=username, password=password)
    if auth_success:
        out['outcome'] = 1
    return out
        

config = bruteloops.models.Config(
    authentication_callback = auth_success,
    db_file = '/tmp/tmp.db')
``````

Then a [`BruteForcer`](#bruteloops.brute.BruteForcer) object can be instantiated
to [`launch`](#bruteloops.brute.BruteForcer.launch) the attack.

``````python
# Create the object
bf = bruteloops.brute.BruteForcer(config=config)

# Start the attack.
# Blocks until completion or interruption.
bf.launch()
``````

------

::: bruteloops.brute

