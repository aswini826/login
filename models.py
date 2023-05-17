from database import Base
from sqlalchemy import Column, Integer, String, ForeignKey


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)
    register_number = Column(Integer, unique=True)
    phone = Column(Integer)
    date_of_birth = Column(String)
    course = Column(String)


class Login(Base):
    __tablename__ = 'login'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
