from sqlalchemy import (Column, Integer, String, DateTime, ForeignKey, func,
        text, Boolean, Float, Enum, UniqueConstraint, Table)
from sqlalchemy import create_engine
from sqlalchemy.orm import relationship, backref, sessionmaker, close_all_sessions
from sqlalchemy.ext.declarative import declarative_base
import enum

Base = declarative_base()

class Username(Base):
    __tablename__ = 'usernames'
    id = Column(Integer, primary_key=True,
        doc='Username id')
    value = Column(String, nullable=False, unique=True,
        doc='Username value')
    recovered = Column(Boolean, default=False,
        doc='Determines if a valid password has been recovered')
    last_time = Column(Float, default=-1.0,
        doc='Last time when username was targeted for authentication')
    future_time = Column(Float, default=-1.0,
        doc='Time when username can be targeted for authentication again')
    passwords = relationship("Password", secondary="credentials")
    credentials = relationship("Credential")

    def __repr__(self):

        return f'<Username(id={self.id}, value={self.value}, '\
            f'recovered={self.recovered} last_time={self.last_time} '\
            f'future_time={self.future_time})>'

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True, doc='Password id')
    value = Column(String, nullable=False, unique=True,
        doc='Password value')
    usernames = relationship("Username", secondary="credentials")
    credentials = relationship("Credential")

    def __repr__(self):

        return f'<Password(id={self.id}, value={self.value})>'

class Credential(Base):
    __tablename__ = 'credentials'
    id = Column(Integer, doc='Credential id',
            autoincrement="auto", primary_key=True)
    username_id = Column(Integer, ForeignKey('usernames.id'), 
            doc='Username id',nullable=False)
    password_id = Column(Integer, ForeignKey('passwords.id'),
            doc='Password id',nullable=False)
    username = relationship("Username", back_populates="credentials")
    password = relationship("Password", back_populates="credentials")
    valid = Column(Boolean, default=False,
        doc='Determines if the credentials are valid')
    guessed = Column(Boolean, default=False,
        doc='Determines if the credentials have been guessed')
    __table_args__ = (UniqueConstraint('username_id','password_id',
        name='_credential_unique_constraint'),)

    def __repr__(self):
        return f'<Credential(id={self.id})>'

class Attack(Base):
    __tablename__ = 'attacks'

    id = Column(Integer, primary_key=True,
        doc='Attack id')
    start_time = Column(Float, nullable=False, doc='Time of attack initialization')
    end_time = Column(Float, nullable=True, doc='Time of attack end')
    complete = Column(Boolean, default=False,
        doc='Determines if the attack completed')
    type = Column(String, nullable=False,
        doc='Type of attack')

    def __repr__(self):

        return f'<Attack(id={self.id}, '\
            f'status={self.status}, '\
            f'attack_type={self.type}, '\
            f'start_time={self.start_time}, '\
            f'end_time={self.end_time}, '\
            f'complete={self.complete}'\
            ')>'
