# Models

Pydantic models are used to validate inputs and outputs from programs
that implement BruteLoops while also providing objects for attack
configuration and management.

## Key Models

- [`bruteloops.models.Config`](#bruteloops.models.Config) provides the
  primary configuration object passed to `BruteLoops.brute.BruteForcer`
  to perform BruteForce attacks.
- [`bruteloops.models.Breaker`](#bruteloops.models.Breaker) defines
  the structure used for stopping attacks when specific exceptions occur.
- [`bruteloops.models.ThresholdBreaker`](#bruteloops.models.ThresholdBreaker)
  extends `Breaker` such that an execption may occur multiple times within
  an established timeframe prior to ending the attack.

---

::: bruteloops.models
