#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging
from os import path
import bottle, utils
from bottle import route, template, request
from db import *

logger = logging.getLogger('records')
app = bottle.default_app()
sess = app.config['db.session']

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
    recs = recs.order_by(Records.starttime)
    start, stop, page, pagemax = utils.paging(recs)
    return template(
        'recs.html', page=page, pagemax=pagemax,
        recs=recs.slice(start, stop))

@route('/rec/<id:int>')
@utils.chklogin('audit')
def _show(session, id):
    pass

@route('/out/<id:int>')
@utils.chklogin('audit')
def _show(session, id):
    rec = sess.query(Records).filter_by(id=id).scalar()
    filepath = path.join(
        app.config.get('file.basedir'),
        rec.starttime.strftime('%Y%m%d'),
        '%d.out' % rec.id)
    with open(filepath, 'rb') as fi:
        d = fi.read(1024)
        while d:
            yield d
            d = fi.read(1024)

@route('/adt/')
def _list():
    pass

@route('/adt/<adt:int>')
def _show(audit):
    pass
