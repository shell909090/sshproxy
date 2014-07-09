#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-03
@author: shell.xu
'''
import os, sys, operator
import bcrypt, sqlalchemy
from sqlalchemy import desc, or_, Table, Column, Integer, String
from sqlalchemy import DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

__all__ = [
    'Users', 'Pubkeys', 'Hosts', 'Accounts', 'GroupGroup', 'Groups',
    'Records', 'RecordLogs', 'AuditLogs',
    'ALLRULES', 'PERMS', 'ALLPERMS',
    'crypto_pass', 'check_pass', 'is_parent', 'cal_group',
    'sqlalchemy', 'desc', 'or_']

Base = declarative_base()

ALLRULES = ['admin', 'users', 'hosts', 'groups', 'audit']
PERMS = ['shell', 'scpfrom', 'scpto', 'tcp', 'agent']

addx = lambda c: lambda x: c + x
ALLPERMS = map(addx('+'), PERMS) + map(addx('-'), PERMS)

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
    host = Column(String, index=True, unique=True, nullable=False)
    hostname = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    proxycommand = Column(String)
    proxyaccount = Column(Integer, ForeignKey('accounts.id', use_alter=True, name='hosts_proxy_account'))
    proxy = relationship("Accounts", foreign_keys=[proxyaccount,])
    hostkeys = Column(String, nullable=False)

class Accounts(Base):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True)
    account = Column(String, index=True, nullable=False)
    hostid = Column(Integer, ForeignKey("hosts.id"))
    host = relationship("Hosts", backref='accounts', foreign_keys=[hostid,])
    key = Column(String)
    password = Column(String)
    __table_args__ = (
        UniqueConstraint('account', 'hostid', name='account_host'),)

user_group = Table(
    'user_group', Base.metadata,
    Column('users_username', String, ForeignKey('users.username')),
    Column('groups_id', Integer, ForeignKey('groups.id')))

account_group = Table(
    'account_group', Base.metadata,
    Column('accounts_id', Integer, ForeignKey('accounts.id')),
    Column('groups_id', Integer, ForeignKey('groups.id')))

class GroupGroup(Base):
    __tablename__ = 'group_group'
    id = Column(Integer, primary_key=True)
    childid = Column(Integer, ForeignKey('groups.id'))
    parentid = Column(Integer, ForeignKey('groups.id'))
    child = relationship('Groups', backref='parents', foreign_keys=[childid,])
    parent = relationship('Groups', backref='children', foreign_keys=[parentid,])

class Groups(Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True)
    name = Column(String, index=True, unique=True)
    users = relationship("Users", backref='groups', secondary=user_group)
    accounts = relationship("Accounts", backref='groups', secondary=account_group)
    perms = Column(String)

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
    rec = relationship('Records')
    time = Column(DateTime, nullable=False, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))
    type = Column(String, nullable=False)
    log1 = Column(String)
    log2 = Column(String)
    num1 = Column(Integer)

class AuditLogs(Base):
    __tablename__ = 'auditlogs'
    id = Column(Integer, primary_key=True)
    time = Column(DateTime, server_default=sqlalchemy.text('CURRENT_TIMESTAMP'))
    username = Column(String, ForeignKey('users.username'))
    level = Column(Integer)
    log = Column(String)

def is_parent(child, parent):
    if child == parent: return True
    return any(gg.parent == parent or is_parent(gg.parent, parent)
               for gg in child.parents)

def cal_group(user, acct):
    ag = acct.groups
    def search(g, perms):
        perms = perms | set(g.perms.split(','))
        if g in ag: return perms
        return search_list([gg.parent for gg in g.parents], perms)
    def search_list(gl, perms):
        l = filter(bool, [search(g, perms) for g in gl])
        return set() if not l else reduce(operator.and_, l)
    rslt = {}
    for p in search_list(user.groups, set()):
        rslt.setdefault(p[1:], []).append(p[0])
    return [k for k, l in rslt.items() if ('-' not in l) and ('+' in l)]

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

    # import pubkey for user
    if '-x' in optdict:
        u = sess.query(Users).filter_by(username=optdict['-x']).one()
        with open(args[0], 'rb') as fi:
            for line in fi:
                pubkey, name = line.strip().split()[1:]
                sess.add(Pubkeys(name=name, user=u, pubkey=pubkey))

    # create host and import hostkey
    if '-m' in optdict:
        hostkeys = subprocess.check_output(["ssh-keyscan", "-t", "rsa,dsa,ecdsa", args[1]])
        sess.add(Hosts(host=args[0], hostname=args[1], port=22, hostkeys=hostkeys))

    # import private key and create account
    if '-p' in optdict:
        account, h = optdict['-p'].split('@')
        host = sess.query(Hosts).filter_by(host=h).one()
        with open(args[0], 'rb') as fi: prikey = fi.read()
        sess.add(Accounts(account=account, host=host, key=prikey))

    sess.commit()

if __name__ == '__main__': main()
