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
def _login():
    return template('login.html')

@route('/usr/login', method='POST')
def _login():
    session = request.environ.get('beaker.session')
    username = request.forms.get('username')
    password = request.forms.get('password')
    logger.debug("login with %s" % username)
    user = sess.query(Users).filter_by(realname=username).filter_by(password=password).first()
    if not user:
        errmsg = "login failed %s." % username
        logger.info(errmsg)
        return template('login.html', errormsg=errmsg)
    logger.info("login successed %s." % username)
    session['username'] = username
    session['perms'] = set(user.perms.split(','))
    return bottle.redirect(request.query.next or '/')

@route('/usr/logout')
@utils.chklogin(next='/')
def _logout(session):
    if 'username' in session:
        del session['username']
    return bottle.redirect(request.query.next or '/')

@route('/pubk/')
@utils.chklogin()
def _list(session):
    logger.debug("username: %s" % session['username'])
    pubkeys = sess.query(UserPubkey).filter_by(realname=session['username'])
    return template('pubk.html', pubkeys=pubkeys)

@route('/pubk/add')
@utils.chklogin()
def _add(session):
    return template('pubk_add.html')

@route('/pubk/add', method='POST')
@utils.chklogin()
def _add(session):
    keys = request.forms.get('keys')
    for line in keys.splitlines():
        pubkey, name = line.strip().split()[1:]
        pubkey = pubkey.replace('\r', '').replace('\n', '')
        pkey = sess.query(UserPubkey).filter_by(pubkey=pubkey).first()
        if not pkey:
            sess.add(AuditLogs(
                realname=session['username'],
                log='add pubkey %s' % pubkey))
            sess.add(UserPubkey(
                name=name, realname=session['username'], pubkey=pubkey))
        elif pkey.realname != session['username']:
            sess.rollback()
            return 'some of your pubkey has been used by other user.'
    sess.commit()
    return bottle.redirect('/pubk/')

@route('/pubk/<pubk:int>/rem')
@utils.chklogin()
def _remove(session, pubk):
    pubkey = sess.query(UserPubkey).filter_by(id=pubk).first()
    if pubkey.realname != session['username']:
        return "can't delete a pubkey not belongs to you."
    logger.debug('delete pubkey: %d' % pubkey.id)
    sess.add(AuditLogs(
        realname=session['username'], log='delete pubkey %s' % pubkey.pubkey))
    sess.delete(pubkey)
    sess.commit()
    return bottle.redirect('/pubk/')

@route('/usr/')
@utils.chklogin('users')
def _list(session):
    return template('usr.html', users=sess.query(Users))

@route('/usr/add')
@utils.chklogin('users')
def _add(session):
    pass

@route('/usr/<username>/edit')
@utils.chklogin('users')
def _edit(session, username):
    pass

@route('/usr/edit')
@utils.chklogin()
def _edit(session):
    return template('usr_edit.html', users=sess.query(Users))

@route('/usr/edit', method='POST')
@utils.chklogin()
def _edit(session):
    pass

@route('/usr/<username>/rem')
@utils.chklogin('users')
def _remove(session, username):
    user = sess.query(Users).filter_by(realname=username).first()
    if not user:
        return '%s not exists'
    logger.debug('delete user: %s' % user.realname)
    sess.add(AuditLogs(
        realname=session['username'], log='delete user %s' % username))
    sess.delete(user)
    sess.commit()
    return bottle.redirect('/usr/')
