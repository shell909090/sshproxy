#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging
import bottle, utils
from bottle import route, template, request
from sqlalchemy import and_
from db import *

logger = logging.getLogger('users')
app = bottle.default_app()

sess = app.config['db.session']

@route('/usr/login')
def login():
    return template('login.html')

@route('/usr/login', method='POST')
def login():
    session = request.environ.get('beaker.session')
    username = request.forms.get('username')
    password = request.forms.get('password')
    logger.debug("login with %s" % username)
    rslt = list(sess.query(Users).filter(Users.realname==username).filter(Users.password==password))
    if rslt:
        logger.info("login successed %s." % username)
        session['username'] = username
        return bottle.redirect(request.query.next or '/')
    logger.Info("login failed %s." % username)
    return template('login.html')

@route('/pubk/')
@utils.chklogin()
def _list():
    session = request.environ.get('beaker.session')
    logger.debug("username: %s" % session['username'])
    pubkeys = sess.query(UserPubkey).filter(UserPubkey.realname==session['username'])
    return template('pubkey_list.html', pubkeys=pubkeys)

@route('/pubk/add')
def _add():
    return template('pubkey_add.html')

@route('/pubk/add', method='POST')
def _add():
    return bottle.redirect('/pubk/')

@route('/pubk/<pubk:int>/rem')
def remove(pubk):
    pubkeys = sess.query(UserPubkey).filter(UserPubkey.id==pubk)
    logger.debug('delete: %s' % ','.join(str(p.id) for p in pubkeys))
    map(sess.delete, pubkeys)
    sess.commit()
    return bottle.redirect('/pubk/')

@route('/usr/')
def lists():
    conn = app.config['db.conn']
    cur = conn.cursor()
    for row in cur.execute('SELECT * FROM users'):
        print row
    return ""

@route('/usr/add')
def users_add():
    pass

@route('/usr/<username>/edit')
def users_edit(username):
    pass

@route('/usr/<username>/rem')
def users_remove(username):
    pass
