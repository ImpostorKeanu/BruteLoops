!!! note

    To learn about database schema, see [`bruteloops.sql`](/pkg-docs/sql)

This module provides classes for managing databases and
resource records.

- [`bruteloops.db_manager.Manager`](#bruteloops.db_manager.Manager) is the
  fastest way to integrate these capabilities into your application.
- [`bruteloops.db_manager.DBMixin`](#bruteloops.db_manager.DBMixin) can be
  used as a parent class if required.

# Example

This would create a `bruteloops.db_manager.Manager` instance and a supporting
database file, followed by inserting username and password values.

!!! tip

    Though this example imports values directly from a `list`,
    it's possible to import values from files by setting the
    `is_file` flag to `True`. Each element in `container` would
    then be treated as a path to a file of newline delimited
    values to import.

``````python
from bruteloops.db_manager import Manager

# Create the manager
mgr = Manager(db_file='/tmp/test.db')

# Insert usernames
mgr.manage_values(
    model='username',
    container=['u1','u2','u3']
)

# Insert passwords
mgr.manage_values(
    model='password',
    container=['p1','p2','p3'],
)

# Insert credential values
mgr.manage_credentials(
    as_credentials=True,
    container=['u4:p4','u5:p5'],
    associate_spray_values=True
)
``````

---

::: bruteloops.db_manager
