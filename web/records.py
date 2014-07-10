#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, time, struct, logging
from os import path
import bottle, utils
from bottle import route, template, request
from db import *

logger = logging.getLogger('records')
app = bottle.default_app()
sess = app.config.get('db.session')

def guess_datetime(s):
    return

def adv_query(objs, q):
    for sq in q.split():
        if (sq.startswith("'") and sq.endswith("'")) or ':' not in sq:
            objs = objs.filter(or_(
                    Records.username.like('%'+sq+'%'),
                    Records.account.like('%'+sq+'%'),
                    Records.host.like('%'+sq+'%')))
            continue

        cmd, args = sq.split(':', 1)
        cmd = cmd.lower()
        if cmd == 'user':
            objs = objs.filter(Records.username.like('%'+sq+'%'))
        elif cmd == 'account':
            objs = objs.filter(Records.account.like('%'+sq+'%'))
        elif cmd == 'host':
            objs = objs.filter(Records.host.like('%'+sq+'%'))
        elif cmd == 'time':
            if args[0] == '<':
                objs = objs.filter(Records.starttime < guess_datetime(args[1:]))
            elif args[0] == '>':
                objs = objs.filter(Records.starttime > guess_datetime(args[1:]))
            elif args[0] == '=':
                objs = objs.filter(Records.starttime == guess_datetime(args[1:]))
        elif cmd == 'cmd':
            raise Exception('not support yet')
        else: raise Exception('unknow command')
    return objs

@route('/rec/')
@utils.chklogin('audit')
def _list(session):
    recs = sess.query(Records)
    q = request.query.q
    if q:
        try: recs = adv_query(recs, q)
        except Exception, e:
            return str(e)
    recs = recs.order_by(desc(Records.starttime))
    utils.log(logger, 'view record list.')
    sess.commit()
    return utils.paged_template('recs.html', _recs=recs)

@route('/rec/<id:int>')
@utils.chklogin('audit')
def _show(session, id):
    rec = sess.query(Records).filter_by(id=id).scalar()
    if not rec:
        return 'rec not exist.'
    reclogs = sess.query(RecordLogs).filter_by(recordid=id).order_by(RecordLogs.time)
    utils.log(logger, 'view record log list id: %d, start: %s, dest: %s@%s.' % (
        rec.id, rec.starttime.strftime('%Y%m%d %H:%M:%S'), rec.account, rec.host))
    sess.commit()
    return utils.paged_template('rec.html', _reclogs=reclogs)

header = struct.Struct('>BH')
def read_sublog(s, b):
    while True:
        d = s.read(3)
        if not d: return
        t, l = header.unpack(d)
        d = s.read(l)
        if b != t: continue
        yield d
        time.sleep(0.2)

@route('/rlog/<id:int>')
@utils.chklogin('audit')
def _show(session, id):
    reclog = sess.query(RecordLogs).filter_by(id=id).scalar()
    if not reclog:
        yield 'reclog not exist.'
        return
    filepath = path.join(
        app.config.get('file.basedir'),
        reclog.rec.starttime.strftime('%Y%m%d'), '%d.rec' % reclog.id)
    utils.log(logger, 'view sess id: %d, start: %s.' % (
        reclog.id, reclog.time.strftime('%Y%m%d %H:%M:%S')))
    sess.commit()
    with open(filepath, 'rb') as fi:
        for d in read_sublog(fi, 2): yield d

@route('/adt/')
@utils.chklogin('audit')
def _list(session):
    audits = sess.query(AuditLogs)
    audits = audits.order_by(desc(AuditLogs.id))
    utils.log(logger, 'view audit list.')
    sess.commit()
    return utils.paged_template('adts.html', _audits=audits)
