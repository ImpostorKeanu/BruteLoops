# SQL Components

BruteLoops uses [SQLAlchemy](https://www.sqlalchemy.org/) to manage
and query [SQLite](https://www.sqlite.org/index.html) databases,
thus facilitating SQL queries when selecting credentials to guess.

## Record (Resource) Types

!!! note

    Applications that implement BruteLoops do not need to worry
    about managing any of these values. All resources are managed
    by [`bruteloops.db_manager`](/pkg-docs/db_manager) and other
    supporting logic at runtime.

There are 4 main types of resources in the database:

1. `attack` - Describes attacks and when they were executed.
2. `username` - Representing accounts.
3. `password` - Passwords that are to be guessed for a username.
4. `credential` - A unit consisting of both a `username` and a
  password pair. This is implemented as a lookup table.

There are 2 additional rources that are managed by BruteLoops
indirectly:

- `Credential` - Represents a relationship between a `username`
  and a `password`.
- `StrictCredential` - Similar to a `Credential` but the
  password is not sprayable. These records are maintained as an
  efficient lookup table, thus minimizing query times during
  attack execution.

## Database Schema

The following Mermaid diagram illustrates the database schema.

``````mermaid
erDiagram

Attack {
    float start_time
    float end_time
    bool  complete
}

Username {
    string value
    bool recovered
    bool actionable
    bool priority
    float last_time
    float future_time
}

Password {
    string value
    bool priority
    bool sprayable
}

Credential {
    int username_id FK
    int password_id FK
    bool valid
    bool guessed
}

PriorityCredential {
    int credential_id FK
}

StrictCredential {
    int credential_id FK
}    

Credential ||--o{ Username : has
Credential ||--o{ Password : has
Credential |o--|| PriorityCredential : has
Credential |o--|| StrictCredential : has
``````

::: bruteloops.sql
