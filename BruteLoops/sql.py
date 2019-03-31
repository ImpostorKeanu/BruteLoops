from sqlalchemy import (Column, Integer, String, DateTime, ForeignKey, func,
        text, Boolean, Float, Enum)
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
    last_password_id = Column(Integer, ForeignKey('passwords.id'),
        default=0,
        doc='Password associated with a given username')
    recovered = Column(Boolean, default=False,
        doc='Determines if a valid password has been recovered')
    last_time = Column(Float, default=-1.0,
        doc='Last time when username was targeted for authentication')
    future_time = Column(Float, default=-1.0,
        doc='Time when username can be targeted for authentication again')

    def __repr__(self):

        return f'<Username(id={self.id}, value={self.value}, '\
            f'last_password_id={self.last_password_id} recovered='\
            f'{self.recovered} last_time={self.last_time} '\
            f'future_time={self.future_time}'\
            ')>'

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True, doc='Password id')
    value = Column(String, nullable=False, unique=True,
        doc='Password value')
#    usernames = relationship('Username',
#        primaryjoin=(
#            'and_(id == Username.last_password_id,'\
#            'Username.recovered == True)'
#        ),
#        doc='Usernames associated with a given password',
#        backref=('password')
#    )

    def __repr__(self):

        return f'<Password(id={self.id}, value={self.value})>'

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
