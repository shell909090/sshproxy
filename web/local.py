#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-10
@author: shell.xu
'''
import os, sys, logging
import bottle, utils
from bottle import route, template, request
from db import *

logger = logging.getLogger('local')
app = bottle.default_app()
sess = app.config['db.session']

def chklocal(func):
    def _inner(*p, **kw):
        ip = request.remote_route[0] if request.remote_route else request.remote_addr
        if not ip.startswith('127.0.0'): return 'sorry'
        return func(*p, **kw)
    return _inner

@bottle.route('/l/cfg')
@chklocal
@utils.jsonenc
def _config():
    r = dict([(k[6:], v) for k, v in app.config.iteritems()
              if k.startswith('proxy.')])
    with open(r['hostkey'], 'rb') as fi: r['hostkey'] = fi.read()
    return r

@route('/l/pubk')
@chklocal
def _query():
    pubk = sess.query(Pubkeys).filter_by(pubkey=request.query.pubkey).scalar()
    if not pubk:
        return {'errmsg': 'pubkey not exist.'}
    return {'name': pubk.name, 'username': pubk.username}

def acct_dict(acct):
    return {'hostid': acct.host.id, 'hostname': acct.host.hostname,
            'port': acct.host.port, 'hostkey': acct.host.hostkeys,
            'accountid': acct.id, 'account': acct.account,
            'key': acct.key, 'password': acct.password}

@route('/l/h')
@chklocal
@utils.jsonenc
def _query():
    username = request.query.get('username')
    account = request.query.get('account')
    host = request.query.get('host')
    if not all([username, account, host]):
        return {'errmsg': 'username or account or host is empty.'}

    user = sess.query(Users).filter_by(username=username).scalar()
    if not user:
        return {'errmsg': 'user not exist.'}
    acct = sess.query(Accounts).filter_by(account=account).\
        join(Accounts.host).filter_by(host=host).scalar()
    if not acct:
        return {'errmsg': 'account not exist.'}

    r = acct_dict(acct)
    r['perms'] = cal_group(user, acct)
    if acct.host.proxy:
        r['proxy'] = acct_dict(acct.host.proxy)
        r['proxycommand'] = acct.host.proxycommand
    return r


@route('/l/rec', method='POST')
@chklocal
@utils.jsonenc
def _add():
    username = request.forms.get('username')
    account = request.forms.get('account')
    host = request.forms.get('host')
    if not (username and account and host):
        return {'errmsg': 'username or account or host is empty.'}
    rec = Records(username=username, account=account, host=host)
    sess.add(rec)
    sess.commit()
    return {'recordid': rec.id, 'starttime': rec.starttime.isoformat()}

@route('/l/end', method='POST')
@chklocal
@utils.jsonenc
def _end():
    recordid = request.forms.get('recordid')
    if not id:
        return {'errmsg': 'recordid empty'}
    rec = sess.query(Records).filter_by(id=recordid).scalar()
    if not rec:
        return {'errmsg': 'rec not exist.'}
    rec.endtime = sqlalchemy.text('CURRENT_TIMESTAMP')
    sess.commit()
    return

@route('/l/rlog', method='POST')
@chklocal
@utils.jsonenc
def _add():
    recordid = request.forms.get('recordid')
    if not recordid:
        return {'errmsg': 'recordid empty'}
    rlog = RecordLogs(
        recordid=recordid,
        type=request.forms.get('type'),
        log1=request.forms.get('log1'),
        log2=request.forms.get('log2'),
        num1=request.forms.get('num1'))
    sess.add(rlog)
    sess.commit()
    return {'id': rlog.id}

@route('/l/rev')
@chklocal
@utils.jsonenc
def _review():
    username = request.query.get('username')
    reclogid = int(request.query.get('recordlogid'))
    if not all([username, reclogid]):
        return {'errmsg': 'username or reclogid is empty.'}

    user = sess.query(Users).filter_by(username=username).scalar()
    if not user:
        return {'errmsg': 'user not exist.'}
    reclog = sess.query(RecordLogs).filter_by(id=reclogid).scalar()
    if not reclog:
        return {'errmsg': 'reclog not exist.'}

    r = {'access': 'audit' in user.perms.split(','),
         'time': reclog.rec.starttime.isoformat()}
    if not r['access']: return r

    log = 'view sess id: %d' % reclogid
    logger.info(log)
    sess.add(AuditLogs(username=username, log=log))
    sess.commit()
    return r
