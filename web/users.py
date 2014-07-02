#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging
import bottle, utils
from bottle import route, template, request

logger = logging.getLogger('users')
app = bottle.default_app()

@route('/usr/login')
def login():
    return template('login.html')

@route('/usr/login', method='POST')
def login():
    session = request.environ.get('beaker.session')
    username = request.forms.get('username')
    password = request.forms.get('password')
    logger.debug("login with %s" % username)
    cur = app.config['db.conn'].cursor()
    cur.execute('SELECT * FROM users WHERE realname=? AND password=?',
                (username, password))
    if cur.fetchone():
        logger.info("login successed %s." % username)
        session['username'] = username
        return bottle.redirect(request.query.next or '/')
    logger.Info("login failed %s." % username)
    return template('login.html')

@route('/pubk/')
@utils.chklogin()
def _list():
    session = request.environ.get('beaker.session')
    cur = app.config['db.conn'].cursor()
    logger.debug("username: %s" % session['username'])
    cur.execute('SELECT * FROM user_pubkey WHERE realname=?',
                (session['username'],))
    pubkeys = cur.fetchall()
    print pubkeys
    return ''

@route('/pubk/imp')
def _import():
    pass

@route('/pubk/rem')
def remove():
    pass

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
