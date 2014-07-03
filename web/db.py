#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-03
@author: shell.xu
'''
import os, sys
from sqlalchemy import Table, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

__all__ = ['Users', 'UserPubkey', 'Hosts', 'Accounts',
           'Records', 'RecordLogs', 'AuditLogs', 'allperms']

Base = declarative_base()

allperms = ['admin', 'users', 'hosts', 'accounts', 'records', 'audit']

class Users(Base):
    __tablename__ = 'users'
    realname = Column(String, primary_key=True)
    password = Column(String)
    pubkeys = relationship("UserPubkey")
    perms = Column(String)

class UserPubkey(Base):
    __tablename__ = 'user_pubkey'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    realname = Column(String, ForeignKey('users.realname'))
    pubkey = Column(String)

class Hosts(Base):
    __tablename__ = 'hosts'
    host = Column(String, primary_key=True)
    hostname = Column(String)
    port = Column(Integer)
    proxycommand = Column(String)
    proxyaccount = Column(Integer, ForeignKey('accounts.id'))
    # proxy = relationship("Accounts", foreign_keys=[proxyaccount,], backref='proxyfor')
    hostkeys = Column(String)

class Accounts(Base):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    host = Column(String, ForeignKey("hosts.host"))
    key = Column(String)

class Perms(Base):
    __tablename__ = 'perms'
    realname = Column(String, ForeignKey('users.realname'), primary_key=True)
    username = Column(String, primary_key=True)
    host = Column(String, ForeignKey('hosts.host'), primary_key=True)
    perm = Column(Integer)

class Records(Base):
    __tablename__ = 'records'
    id = Column(Integer, primary_key=True)
    realname = Column(String, ForeignKey('users.realname'))
    username = Column(String)
    host = Column(String, ForeignKey('hosts.host'))
    starttime = Column(DateTime)
    endtime = Column(DateTime)

class RecordLogs(Base):
    __tablename__ = 'recordlogs'
    recordid = Column(Integer, primary_key=True)
    type = Column(Integer)
    filename = Column(String)
    size = Column(Integer)
    remotedir = Column(String)

class AuditLogs(Base):
    __tablename__ = 'auditlogs'
    id = Column(Integer, primary_key=True)
    time = Column(DateTime)
    realname = Column(String, ForeignKey('users.realname'))
    level = Column(Integer)
    log = Column(String)
