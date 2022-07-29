from .errors import BreakerThrownError
from pydantic import BaseModel, Field, validator
from logging import Logger
from typing import (
    List,
    Union,
    Optional,
    Callable,
    Type)
from functools import wraps
import inspect
from enum import IntEnum

class GuessOutcome(IntEnum):

    failed  = -1
    'Failed to guess credentials.'

    invalid = 0
    'Invalid credentials.'

    valid   = 1
    'Valid credentials.'

class OutputModel(BaseModel):

    outcome: GuessOutcome
    'Guess outcome.'

    username: str
    'Username that was guessed.'

    password: str
    'Password that was guessed.'

    actionable: bool = True
    'Determines if the username is still actionable, i.e. '
    'removed/disabled from further guesses.'

    events: List[str] = Field(default_factory=list)
    'Events to log.'

    def dict(self, *args, **kwargs):
        out = super().dict(*args, **kwargs)
        out['outcome'] = out['outcome'].value
        return out

class OutputsModel(BaseModel):
    __root__: List[OutputModel]
    'List of output objects.'

class BreakerModel(BaseModel):
    '''Base class all breakers can inherit from.
    '''

    exception_classes: List[Type[Exception]] = Field(
        default_factory=list)
    'Exception classes the breaker will act on.'

class BreakersModel(BaseModel):
    '''A list of breakers to handle exceptions.
    '''

    __root__: List[BreakerModel]

class TresholdBreakerModel(BreakerModel):

    threshold: int = 1
    ('Maximum number of times the breaker can be handled before '
    'throwing an exception.')

    count: int = 0
    'Count of times handle has been called.'

    @validator('count')
    def h_count_is_positive(cls, c):
        'Count must be positive or zero.'

        if c < 0:
            raise ValidationError(
                f'count must be >-1, got {c}')

        return c

    @validator('threshold')
    def v_thresh(cls, t):
        'Threshold must be >=1.'

        if t < 1:
            raise ValidationError(
                f'threshold must be greater >=1, got {t}')

        return v
