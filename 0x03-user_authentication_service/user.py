#!/usr/bin/env python3
import requests
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import String, Integer, Column


Base = declarative_base()

class User(Base):
    """User database model"""

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=True)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)