Breakers provide a method of terminating an attack when an exception
is raised. They intend to behave like circuit breakers, breaking only
when some condition manifests.

## The Two Types of Breakers

BruteLoops offers two types of breakers:

- [`bruteloops.models.Breaker`](#bruteloops.models.Breaker)
    - The standard breaker.
    - The control loop is immediately terminated when exceptions handled by
      this class are raised.
- [`bruteloops.models.ThresholdBreaker`](#bruteloops.models.ThresholdBreaker)
    - Inherits from the standard breaker.
    - Allows for a configurable number of exceptions to be raised before
      becoming tripped and terminating the control loop.
    - It's also possible to configure a reset specification for this type
      of breaker.
        - This means that a number of matching exceptions must be raised
          within a window of time before the control loop is terminated.

## Examples

!!! note

    - [`bruteloops.models.Config`](/pkg-docs/models/#bruteloops.models.Config)
      accepts a list of one or more breakers.
    - A blend of
      [`bruteloops.models.Breaker`](#bruteloops.models.Breaker) and
      [`bruteloops.models.ThresholdBreaker`](#bruteloops.models.ThresholdBreaker)
      can be provided.
    - Custom exception classes can be provided so long as they inherit from
      `Exception` or `BaseException`.

### Standard Breaker Configuration

A standard breaker always raises `bruteloops.errors.BreakerTrippedError`
when a handled exception class is raised during attack execution.

This configuration would result in the breaker being thrown after the
first `ConnectionError` is raised.

``````python
import bruteloops
breakers = [bruteloops.models.Breaker(
    exception_classes=[ConnectionError])
``````

### Threshold Breaker Configuration

Configure a breaker that would reset the count after 10 minutes
with no `ConnectionError`s being raised.

``````python
import bruteloops
breakers = [bruteloops.models.ThresholdBreaker(
    threshold=5,
    exception_classes=[ConnectionError],
    reset_spec='10m')]
``````

### Complete Configuration Example

This example produces a working
[`bruteloops.models.Config`](/pkg-docs/models/#bruteloops.models.Config).

!!! warning

    - This example *does not* represent a well-considered attack
      configuration.
    - This example is naive. It does not raise the custom
      `LockoutException` class and the callback always returns `True`.

``````python
import bruteloops

class LockoutException(Exception):
    pass

breakers = [
    bruteloops.models.ThresholdBreaker(
        exception_classes=[LockoutException],
        threshold=5,
        reset_spec='5m'),
    bruteloops.models.ThresholdBreaker(
        exception_classes=[ConnectionError],
        threshold=20,
        reset_spec='20m')]

config = bruteloops.models.Config(
    db_file='/tmp/test.db',
    breakers=breakers,
    authentication_callback=lambda username,password: True)
``````

---

## Standard Breaker

::: bruteloops.models.Breaker

---

## Threshold Breaker

::: bruteloops.models.ThresholdBreaker
