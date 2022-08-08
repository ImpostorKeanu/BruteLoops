# Database Management

BruteLoops provides classes to simplify management of databases
and database records.

- Instantiate a [`Manager`](#bruteloops.db_manager.Manager) object to
  quickly create a SQLite database and begin managing records.
- See [`DBMixin`](#bruteloops.db_manager.DBMixin) for relevant management
  methods, such as:
    - [`DBMixin.manage_values`](#bruteloops.db_manager.DBMixin.manage_values)
      to manage individual `username` and `password` records.
    - [`DBMixin.manage_credentials`](#bruteloops.db_manager.DBMixin.manage_credentials)
      to manage credentials.

## Methods for Creating Resource Records

There are individual methods for creating resource records:

- [`insert_username_records`](#bruteloops.db_manager.DBMixin.insert_username_records)
- [`insert_password_records`](#bruteloops.db_manager.DBMixin.insert_password_records)
- [`insert_credential_records`](#bruteloops.db_manager.DBMixin.insert_credential_records) (`as_credentials` set to `False`)

`insert_username_records` and `insert_password_records` have an
obvious purpose: they insert records into their respective
database table.

However, `insert_credential_records` deserves greater explanation.
This method:

- Accepts a container of delimited strings, e.g. `username:password`
- The string is broken out into individual username and password
  record values and then inserted into the database.
- When the `as_credentials` argument is `False`, the values are
  imported and treated as spray values, i.e. the passwords will
  be tried for all usernames.
- When the `as_credentials` argument is set to `True`, they will be
  be treated as `StrictCredentials`, i.e. the password will be
  guessed for usernames which it has been expressly configured for.
    - However, all other passwords will be guessed for the username
      after all `StrictCredentials` have been exhausted.

### Methods for Deleting Resource Records

The following methods follow the same semantics described above,
except they delete records from the database.

- [`delete_username_records`](#bruteloops.db_manager.DBMixin.delete_username_records)
- [`delete_password_records`](#bruteloops.db_manager.DBMixin.delete_password_records)
- [`delete_credential_records`](#bruteloops.db_manager.DBMixin.delete_credential_records)

### Resource Management Methods

These methods compliment previously described methods by providing
logic to handle containers of various types:

_Methods:_

- [`manage_values`](#bruteloops.db_manager.DBMixin.manage_values) - Inserts/deletes usernames and passwords.
- [`manage_credentials`](#bruteloops.db_manager.DBMixin.manage_credentials) - Inserts/deletes credentials.

_Container Types:_

Management methods always accept a list of strings and a flag that
determines how values in the list should be treated, e.g. the
`is_file` flag indicates that each value points to a file of
values.

- When no `is_file` or `is_csv_file` flag is set, the values
  are treated as the records to import.
- When `is_file` is `True`: values are file paths to newline
  delimited files for opening.
- When `is_csv_file` is `True`: values are file paths to CSV
  files for parsing. (`manage_credential_values` only)

## Examples

### Usernames from a File, Passwords from List

This example imports a list of usernames and passwords into
a newly created database.

_The Username File (`/tmp/usernames.txt`)_

```
user1
user2
```

_Calling the Methods_

This would populate the database with:

- 2 usernames from file
- 3 spray passwords directly
- Produce a total of 6 credentials to guess
  - `usernames*passwords=total_credentials`
  - `2*3=6`

```python
import bruteloops
dbm = bruteloops.db_manager.Manager('/tmp/test.db')

# Import the usernames from disk first
dbm.manage_values(
    model='username',
    container=['/tmp/usernames.txt'],
    is_file=True,
    associate_spray_values=False)

# Import passwords and associate them with all usernames
dbm.manage_values(
    model='password',
    container=['p1', 'p2', 'p3'],
    associate_spray_values=True)
```

------

::: bruteloops.db_manager
