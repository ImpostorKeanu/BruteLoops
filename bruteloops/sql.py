from sqlalchemy import (Column, Integer, String, DateTime, ForeignKey, 
        Boolean, Float, UniqueConstraint)
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Username(Base):
    '''Tracks username values.

    Attributes:
        id: Row ID.
        value: String value.
        recovered: Determines if a valid password has been
          recovered for the username..
        actionable: Determines if guesses should be made for a given
          username, allowing implementers to disable invalid values
          at execution time.
        priority: Determines if the username should be prioritized
          over other non-priority usernames.
        last_time: Dictates the last time a password was guessed for
          a username.
        future_time: The next time a password can be guessed for a
          username.
        passwords: A relationship with password values established
          via the `credentials` table.
        credentals: A relationship established directly with the
          `credentials` table.

    Notes:
        - For simplicity, timestamps are stored as float values.
        - By default, timestamp values are -1, a value that clearly
          indicates if the timestamp has been set by BruteLoops logic.
    '''

    __tablename__ = 'usernames'
    __mapper_args__ = {'confirm_deleted_rows': False}

    id = Column(Integer, primary_key=True,
        doc='Username id')

    value = Column(String, nullable=False, unique=True,
        doc='Username value')

    recovered = Column(Boolean, default=False,
        doc='Determines if a valid password has been recovered.')

    actionable = Column(Boolean, default=True,
        doc='Determines if the account is actionable, removing '
            'it from additional guesses when set to False.')

    priority = Column(Boolean, default=False,
        doc='Determines if the user is prioritized.')

    last_time = Column(Float, default=-1.0,
        doc='Last time when username was targeted for authentication.')

    future_time = Column(Float, default=-1.0,
        doc='Time when username can be targeted for authentication again.')

    # ORM Relationships
    passwords = relationship("Password",
        secondary="credentials",
        viewonly=True)

    credentials = relationship("Credential",
        cascade="all, delete, delete-orphan")

    def __repr__(self):

        return f'<Username(id={self.id}, value="{self.value}", '\
            f'recovered={self.recovered} last_time={self.last_time} '\
            f'future_time={self.future_time})>'

class Password(Base):
    '''Tracks password values.

    Attributes:
        id: Row ID.
        value: String value.
        priority: Determines if the password should be prioritized
          over other non-priority passwords.
        sprayable: Convenience attribute that determines if a given
          password can be used in spray attacks.
        usernames: A relationship established vai the `credentials`
          table that provides access to all usernames associated with
          the password.
        credentials: A directly relationship to the `credentials`
          table.
    '''

    __tablename__ = 'passwords'
    __mapper_args__ = {'confirm_deleted_rows': False}

    id = Column(Integer, primary_key=True, doc='Password id')

    value = Column(String, nullable=False, unique=True,
        doc='Password value')

    priority = Column(Boolean, default=False,
        doc='Determines if the password is prioritized')

    sprayable = Column(Boolean, default=True,
        doc='Determines if the password can be used as a spray value.')

    # ORM Relationships
    usernames = relationship("Username",
        secondary="credentials",
        viewonly=True)

    credentials = relationship("Credential",
        cascade="all, delete, delete-orphan")

    def __repr__(self):

        return f'<Password(id={self.id}, value="{self.value}")>'

class Credential(Base):
    '''An association, i.e. lookup or join, table used to associate
    usernames with passwords. This avoids bloat of duplicate
    username/password values at the cost of query complexity.

    Attributes:
        id: Row ID.
        username_id: Foreign key to `usernames`.
        password_id: Foreign key to `passwords`.
        password: Relationship to the associated `Password` object.
        username: Relationship to the `Username` object.
        strict_credential: Relationship to the `strict_credentials`
          table.
        valid: Determines if the credential record is valid.
        strict: Determines if the associate password should be used
          in spray attacks.
        guessed: Determines if a guess has been made for the
          credential.
        guess_time: Determines when the credential was guessed.
    '''

    __tablename__ = 'credentials'
    __mapper_args__ = {'confirm_deleted_rows': False}
    __table_args__ = (
            UniqueConstraint('username_id','password_id',
                name='_credential_unique_constraint'),
            )

    id = Column(Integer, doc='Credential id', autoincrement="auto", primary_key=True)

    # Foreign keys
    username_id = Column(Integer, ForeignKey('usernames.id',
        ondelete='CASCADE'), doc='Username id', nullable=False)

    password_id = Column(Integer, ForeignKey('passwords.id',
        ondelete='CASCADE'), doc='Password id', nullable=False)

    # ORM Relationships
    password = relationship("Password", back_populates="credentials")

    username = relationship("Username", back_populates="credentials")

    strict_credential = relationship("StrictCredential",
        back_populates="credential", cascade="all, delete, delete-orphan")

    # Attributes
    valid = Column(Boolean, default=False,
        doc='Determines if the credentials are valid')

    strict = Column(Boolean, default=False,
        doc='Determines if the credentials are strict, i.e. the associated '
          'password should not be used in spray attacks.')

    guessed = Column(Boolean, default=False,
        doc='Determines if the credentials have been guessed')

    guess_time = Column(Float, default=-1.0,
        doc='Time when the guess occurred')

    def __repr__(self):
        return f'<Credential(id={self.id} ' \
               f'username=({self.username.id}) "{self.username.value}" ' \
               f'password=({self.password.id}) "{self.password.value}" ' \
               f'guessed={self.guessed}) >'

class StrictCredential(Base):
    '''A table of credential IDs that are strict. Seemingly redundant,
    this table will generally contain less records than `credentials`
    and responds faster to queries/joins.

    Attributes:
        id: Row ID.
        credential_id: ID of the credential that is strict.
        credential: Relationship to the `Credential` record.

    Notes:
      - Database-level cascade is used to remove records from this
        table.
    '''

    __tablename__ = 'strict_credentials'
    __mapper_args__ = dict(confirm_deleted_rows=False)
    __table_args__ = (
            UniqueConstraint('credential_id',
                name='_unique_credential_id'),
        )

    id = Column(Integer, doc='Credential id',
            autoincrement="auto", primary_key=True)

    credential_id = Column(Integer, ForeignKey('credentials.id',
        ondelete='CASCADE'), doc='Credential id', nullable=False)

    credential = relationship("Credential")

class PriorityCredential(Base):
    '''A table of credential IDs associated with records that are
    associated with either priority usernames or passwords. Similar
    to `StrictCredential`, this table will almost certainly have
    fewer records and will respond quickly to queries.

    Attributes:
        id: Row ID.
        credential_id: ID of the associated credential.
        credential: Relationship to the credential record.

    Notes:
      - Database-level cascade is used to remove records from this
        table.
    '''

    __tablename__ = 'priority_credentials'
    __mapper_args__ = dict(confirm_deleted_rows=False)
    __table_args__ = (
            UniqueConstraint('credential_id',
                name='_unique_credential_id'),
        )

    id = Column(Integer, doc='Priority credential id',
            autoincrement="auto", primary_key=True)

    credential_id = Column(Integer, ForeignKey('credentials.id',
        ondelete='CASCADE'), doc='Credential id', nullable=False)

    credential = relationship("Credential")

class Attack(Base):
    '''A table to track execution of BruteLoops attacks.
    '''

    __tablename__ = 'attacks'
    __mapper_args__ = dict(confirm_deleted_rows=False)

    id = Column(Integer, primary_key=True,
        doc='Attack id')
    start_time = Column(Float, nullable=False,
            doc='Time of attack initialization')
    end_time = Column(Float, nullable=True, doc='Time of attack end')
    complete = Column(Boolean, default=False,
        doc='Determines if the attack completed')

    def __repr__(self):

        return f'<Attack(id={self.id}, '\
            f'status={self.status}, '\
            f'attack_type={self.type}, '\
            f'start_time={self.start_time}, '\
            f'end_time={self.end_time}, '\
            f'complete={self.complete}'\
            ')>'
