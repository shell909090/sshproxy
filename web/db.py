#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-03
@author: shell.xu
'''
import os, sys
import bcrypt, sqlalchemy
from sqlalchemy import Table, Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

__all__ = ['Users', 'Pubkeys', 'Hosts', 'Accounts', 'Groups',
           'Records', 'RecordLogs', 'AuditLogs', 'ALLRULES', 'crypto_pass', 'check_pass']

Base = declarative_base()

ALLRULES = ['admin', 'users', 'hosts', 'accounts', 'groups', 'records', 'audit']

def crypto_pass(p):
    return bcrypt.hashpw(p, bcrypt.gensalt())

def check_pass(p, h):
    return bcrypt.hashpw(p, h) == h

class Users(Base):
    __tablename__ = 'users'
    username = Column(String, primary_key=True)
    password = Column(String, nullable=False)
    deleted = Column(Boolean)
    pubkeys = relationship("Pubkeys", backref='user')
    perms = Column(String, nullable=False)

class Pubkeys(Base):
    __tablename__ = 'pubkeys'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    username = Column(String, ForeignKey('users.username'))
    pubkey = Column(String, index=True, nullable=False)

class Hosts(Base):
    __tablename__ = 'hosts'
    id = Column(Integer, primary_key=True)
    host = Column(String, index=True)
    hostname = Column(String, nullable=False)
    port = Column(Integer)
    proxycommand = Column(String)
    proxyaccount = Column(Integer, ForeignKey('accounts.id', use_alter=True, name='hosts_proxy_account'))
    proxy = relationship("Accounts", foreign_keys=[proxyaccount,])
    hostkeys = Column(String)

class Accounts(Base):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True)
    account = Column(String, index=True, nullable=False)
    hostid = Column(Integer, ForeignKey("hosts.id"))
    host = relationship("Hosts", backref='accounts', foreign_keys=[hostid,])
    key = Column(String)
    __table_args__ = (
        UniqueConstraint('account', 'hostid', name='account_host'),)

class Groups(Base):
    __tablename__ = 'groups'
    username = Column(String, ForeignKey('users.username'), primary_key=True)
    account = Column(String, primary_key=True)
    host = Column(String, ForeignKey('hosts.host'), primary_key=True)
    perm = Column(String)

class Records(Base):
    __tablename__ = 'records'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    account = Column(String)
    host = Column(String)
    starttime = Column(DateTime, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))
    endtime = Column(DateTime)

class RecordLogs(Base):
    __tablename__ = 'recordlogs'
    id = Column(Integer, primary_key=True)
    recordid = Column(Integer, ForeignKey('records.id'))
    time = Column(DateTime, nullable=False)
    type = Column(Integer, nullable=False)
    log = Column(String)
    filename = Column(String)
    size = Column(Integer)
    remotedir = Column(String)

class AuditLogs(Base):
    __tablename__ = 'auditlogs'
    id = Column(Integer, primary_key=True)
    time = Column(DateTime, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))
    username = Column(String, ForeignKey('users.username'))
    level = Column(Integer)
    log = Column(String)

def main():
    import getopt, subprocess, ConfigParser
    optlist, args = getopt.getopt(sys.argv[1:], 'bc:hmp:x:')
    optdict = dict(optlist)
    if '-h' in optdict:
        print main.__doc__
        return

    cfg = ConfigParser.ConfigParser()
    cfg.read(optdict.get('-c', 'web.ini'))
    engine = sqlalchemy.create_engine(cfg.get('db', 'url'))
    sess = sqlalchemy.orm.sessionmaker(bind=engine)()

    if '-b' in optdict:
        Base.metadata.create_all(engine)
        sess.add(Users(
            username='shell', password=crypto_pass('123'),
            perms=','.join(ALLRULES)))

    if '-x' in optdict:
        u = sess.query(Users).filter_by(username=optdict['-x']).first()
        with open(args[0], 'rb') as fi:
            for line in fi:
                pubkey, name = line.strip().split()[1:]
                sess.add(Pubkeys(name=name, user=u, pubkey=pubkey))

    if '-p' in optdict:
        account, h = optdict['-p'].split('@')
        host = sess.query(Hosts).filter_by(host=h).first()
        with open(args[0], 'rb') as fi: prikey = fi.read()
        sess.add(Accounts(account=account, host=host, key=prikey))

    if '-m' in optdict:
        hostkeys = subprocess.check_output(["ssh-keyscan", "-t", "rsa,dsa,ecdsa", args[1]])
        sess.add(Hosts(host=args[0], hostname=args[1], port=22, hostkeys=hostkeys))

    sess.commit()

if __name__ == '__main__': main()
