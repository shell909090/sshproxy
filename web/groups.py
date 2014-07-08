#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-07
@author: shell.xu
'''
import os, sys, logging
import bottle, utils
from bottle import route, template, request
from db import *

logger = logging.getLogger('groups')
app = bottle.default_app()
sess = app.config['db.session']

@route('/grp/')
@utils.chklogin('groups')
def _list(session):
    groups = sess.query(Groups).order_by(Groups.id)
    return utils.paged_template('grp.html', _groups=groups)

@route('/grp/add')
@utils.chklogin('groups')
def _add(session):
    return template('grp_edit.html', group=Groups(perms=''))

@route('/grp/add', method="POST")
@utils.chklogin('groups')
def _add(session):
    name = request.forms.name
    group = sess.query(Groups).filter_by(name=name).scalar()
    if group or not name:
        return template(
            'grp_edit.html', group=Groups(perms=''),
            errmsg='group exist or name illegal')

    perms = set(request.forms.getall('perms')) & set(ALLPERMS)
    perms = ','.join(perms)
    utils.log(logger, 'create group %s, perms: %s' % (name, perms))
    group = Groups(name=name, perms=perms)
    sess.add(group)
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/<id:int>/edit')
@utils.chklogin('groups')
def _edit(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'
    return template('grp_edit.html', group=group)

@route('/grp/<id:int>/edit', method='POST')
@utils.chklogin('groups')
def _edit(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'

    parent = sess.query(Groups).filter_by(name=request.forms.parent).scalar()
    if not parent:
        return 'parent not exist.'
    u = parent
    while u:
        if u == group:
            return template(
                'grp_edit.html', group=group,
                errmsg='Oops, parent looped.')
        u = u.parent

    group.name = request.forms.name

    perms = set(request.forms.getall('perms')) & set(ALLPERMS)
    perms = ','.join(perms)
    group.perms = perms

    group.parent = parent

    utils.log(logger, 'change group name %s => %s, perms: %s => %s, parent: %s' % (
        group.name, request.forms.name, group.perms, perms, request.forms.parent))
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/<id:int>/usrs')
@utils.chklogin('groups')
def _associated(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'
    grpusrs = set([u.username for u in group.users])

    if 'selected' not in session:
        session['selected'] = grpusrs
        return bottle.redirect('/usr/select?next=/grp/%d/usrs' % id)
    usernames = set(session.pop('selected'))

    for u in grpusrs - usernames:
        user = sess.query(Users).filter_by(username=u).scalar()
        if not user:
            sess.rollback()
            return 'some user dont exist.'
        group.users.remove(user)

    for u in usernames - grpusrs:
        user = sess.query(Users).filter_by(username=u).scalar()
        if not user:
            sess.rollback()
            return 'some user dont exist.'
        group.users.append(user)

    utils.log(logger, 'associated users to group %s(%d): %s' % (
        group.name, group.id, ','.join(usernames)))
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/<id:int>/accts')
@utils.chklogin('groups')
def _associated(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'
    grpaccts = set([a.id for a in group.accounts])

    if 'selected' not in session:
        session['selected'] = grpaccts
        return bottle.redirect('/acct/select?next=/grp/%d/accts' % id)
    accounts = set(session.pop('selected'))

    for id in grpaccts - accounts:
        acct = sess.query(Accounts).filter_by(id=id).scalar()
        if not acct:
            sess.rollback()
            return 'some account dont exist.'
        group.accounts.remove(acct)

    for id in accounts - grpaccts:
        acct = sess.query(Accounts).filter_by(id=id).scalar()
        if not acct:
            sess.rollback()
            return 'some account dont exist.'
        group.accounts.append(acct)

    utils.log(logger, 'associated account to group %s(%d): %s' % (
        group.name, group.id, ','.join([str(id) for id in accounts])))
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/<id:int>/rem')
@utils.chklogin('groups')
def _remove(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'

    utils.log(logger, 'del group: %d %s' % (group.id, group.name))
    sess.delete(group)
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/cal')
@utils.chklogin('groups')
def _calculus(session):
    pass

@route('/grp/cal', method='POST')
@utils.chklogin('groups')
def _calculus(session):
    pass
