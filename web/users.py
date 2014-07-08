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
    user = sess.query(Users).filter_by(username=username).scalar()
    if not user or not check_pass(password, user.password):
        errmsg = "login failed %s." % username
        logger.info(errmsg)
        return template('login.html', errmsg=errmsg)
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

@route('/usr/')
@utils.chklogin('users')
def _list(session):
    users = sess.query(Users)
    q = request.query.q
    if q:
        users = users.filter(Users.username.like('%'+q+'%'))
    users = users.order_by(Users.username)
    return utils.paged_template('usr.html', _users=users)

@route('/usr/select')
@utils.chklogin('users')
def _select(session):
    usernames = session.pop('selected')
    users = sess.query(Users).order_by(Users.username)
    return utils.paged_template('usr.html', _users=users, selected=set(usernames))

@route('/usr/select', method='POST')
@utils.chklogin('users')
def _select(session):
    usernames = request.forms.getall('users')
    session['selected'] = usernames
    return bottle.redirect(request.query.next or '/')

@route('/usr/add')
@utils.chklogin('users')
def _add(session):
    return template('usr_edit.html', user=Users(perms=""))

@route('/usr/add', method='POST')
@utils.chklogin('users')
def _add(session):
    username = request.forms.get('username')
    user = sess.query(Users).filter_by(username=username).scalar()
    if user or not username:
        return template(
            'usr_edit.html', user=Users(perms=""),
            errmsg="user exist or illegal username")

    password1 = request.forms.get('password1')
    password2 = request.forms.get('password2')
    if password1 != password2:
        return template(
            'usr_edit.html', users=Users(perms=""),
            errmsg="password not match")

    perms = set(request.forms.getall('perms')) & set(ALLRULES)
    perms = ','.join(perms)
    utils.log(logger, 'create user %s, perms: %s' % (username, perms))
    user = Users(
        username=username, password=crypto_pass(password1), perms=perms)
    sess.add(user)
    sess.commit()
    return bottle.redirect('/usr/')

@route('/usr/<username>/edit')
@utils.chklogin('users')
def _edit(session, username):
    user = sess.query(Users).filter_by(username=username).scalar()
    if not user:
        return 'user not exist.'
    return template('usr_edit.html', user=user)

@route('/usr/<username>/edit', method="POST")
@utils.chklogin('users')
def _edit(session, username):
    user = sess.query(Users).filter_by(username=username).scalar()
    if not user:
        return template(
            'usr_edit.html', user=user,
            errmsg="user not exist")

    password1 = request.forms.get('password1')
    password2 = request.forms.get('password2')
    if all([password1, password2]):
        if password1 != password2:
            return template(
                'usr_edit.html', users=user,
                errmsg="password not match")
        user.password = crypto_pass(password1)
        utils.log(logger, 'change password of user %s.' % username)

    perms = set(request.forms.getall('perms')) & set(ALLRULES)
    perms = ','.join(perms)
    utils.log(logger, 'change perm from %s to %s for user %s' % (
            user.perms, perms, user.username))
    user.perms = perms
    sess.commit()
    return bottle.redirect('/usr/')

@route('/usr/edit')
@utils.chklogin()
def _edit(session):
    user = sess.query(Users).filter_by(username=session['username']).scalar()
    return template('usr_edit.html', user=user, editself=True)

@route('/usr/edit', method='POST')
@utils.chklogin()
def _edit(session):
    user = sess.query(Users).filter_by(username=session['username']).scalar()
    if not user:
        return template(
            'usr_edit.html', user=user, editself=True,
            errmsg="user not exist")

    # FIXME: time limit
    password_old = request.forms.get('password_old')
    if check_pass(password_old, user.password):
        return template(
            'usr_edit.html', users=user, editself=True,
            errmsg="old password not match")

    password1 = request.forms.get('password1')
    password2 = request.forms.get('password2')
    if password1 or password2:
        if password1 != password2:
            return template(
                'usr_edit.html', users=user, editself=True,
                errmsg="password not match")
        user.password = crypto_pass(password1)
        utils.log(logger, 'change password of user %s.' % session['username'])

    perms = set(request.forms.getall('perms')) & set(ALLRULES)
    utils.log(logger, 'change perm from %s to %s for user %s' % (
            user.perms, perms, user.username))
    user.perms = ','.join(perms)
    sess.commit()
    return bottle.redirect('/usr/')

@route('/usr/<username>/rem')
@utils.chklogin('users')
def _remove(session, username):
    user = sess.query(Users).filter_by(username=username).scalar()
    if not user:
        return '%s not exists.' % username
    utils.log(logger, 'delete user: %s' % user.realname)
    sess.delete(user)
    sess.commit()
    return bottle.redirect('/usr/')

@route('/pubk/')
@utils.chklogin()
def _list(session):
    logger.debug("username: %s" % session['username'])
    pubkeys = sess.query(Pubkeys).filter_by(username=session['username'])
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
        pkey = sess.query(Pubkeys).filter_by(pubkey=pubkey).scalar()
        if not pkey:
            utils.log(logger, 'add pubkey %s' % pubkey)
            sess.add(Pubkeys(
                name=name, username=session['username'], pubkey=pubkey))
        elif pkey.username != session['username']:
            sess.rollback()
            return 'some of your pubkey has been used by other user.'
    sess.commit()
    return bottle.redirect('/pubk/')

@route('/pubk/<pubk:int>/rem')
@utils.chklogin()
def _remove(session, pubk):
    pubkey = sess.query(Pubkeys).filter_by(id=pubk).scalar()
    if not pubkey:
        return 'no such a pubkey'
    if pubkey.username != session['username']:
        return "can't delete a pubkey not belongs to you."
    utils.log(logger, 'delete pubkey: %d' % pubkey.id)
    sess.delete(pubkey)
    sess.commit()
    return bottle.redirect('/pubk/')
