#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging
import bottle
from bottle import request, redirect
from db import *

app = bottle.default_app()
sess = app.config['db.session']

LOGFMT = '%(asctime)s.%(msecs)03d[%(levelname)s](%(module)s:%(lineno)d): %(message)s'
def initlog(lv, logfile=None, stream=None, longdate=False):
    if isinstance(lv, basestring): lv = getattr(logging, lv)
    kw = {'format': LOGFMT, 'datefmt': '%H:%M:%S', 'level': lv}
    if logfile: kw['filename'] = logfile
    if stream: kw['stream'] = stream
    if longdate: kw['datefmt'] = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(**kw)

def chklogin(perm=None, next=None):
    def receiver(func):
        def _inner(*p, **kw):
            session = request.environ.get('beaker.session')
            if 'username' not in session or 'perms' not in session:
                return redirect('/usr/login?next=%s' % (next or request.path))
            if perm:
                if hasattr(perm, '__iter__'):
                    if not all([p in session['perms'] for p in perm]):
                        return "you don't have %s permissions" % perm
                elif perm not in session['perms']:
                    return "you don't have %s permissions" % perm
            return func(session, *p, **kw)
        return _inner
    return receiver

def log(logger, log):
    session = request.environ.get('beaker.session')
    logger.info(log)
    sess.add(AuditLogs(username=session['username'], log=log))

def paged_template(tmpl, **kw):
    for k, v in kw.items():
        if k.startswith('_'):
            name, objs = k[1:], v
            break
    del kw['_' + name]

    page = int(request.query.page or 1)
    cnt = objs.count()
    pagenum = int(app.config.get('page.number'))

    start = (page - 1) * pagenum
    stop = min(start + pagenum, cnt)
    kw['pagemax'] = int((cnt-1) / pagenum) + 1
    kw[name] = objs.slice(start, stop)
    return template(tmpl, page=page, **kw)
