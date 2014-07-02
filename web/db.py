#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-03
@author: shell.xu
'''
import os, sys
from sqlalchemy import Table, Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

__all__ = ['Users', 'UserPubkey']

Base = declarative_base()

class Users(Base):
    __tablename__ = 'users'
    realname = Column(String, primary_key=True)
    password = Column(String)
    pubkeys = relationship("UserPubkey")

class UserPubkey(Base):
    __tablename__ = 'user_pubkey'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    realname = Column(String, ForeignKey('users.realname'))
    pubkey = Column(String)
