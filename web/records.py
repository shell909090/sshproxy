#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging
import bottle, utils
from bottle import route, template, request
from db import *


logger = logging.getLogger('records')
app = bottle.default_app()
sess = app.config['db.session']

def adv_query(objs, q):
    return objs

@route('/rec/')
@utils.chklogin('audit')
def _list(session):
    recs = sess.query(Records)
    q = request.query.q
    if q: recs = adv_query(recs, q)
    recs = recs.order_by(Records.starttime)
    start, stop, page, pagemax = utils.paging(recs)
    return template(
        'recs.html', page=page, pagemax=pagemax,
        recs=recs.slice(start, stop))

@route('/rec/<rec:int>')
def _show(rec):
    pass

@route('/adt/')
def _list():
    pass

@route('/adt/<adt:int>')
def _show(audit):
    pass
