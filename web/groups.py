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
@utils.chklogin('admin')
def _list(session):
    groups = sess.query(Groups).order_by(Groups.id)
    return utils.paged_template('grp.html', _groups=groups)

@route('/grp/select')
@utils.chklogin('admin')
def _select(session):
    groups = sess.query(Groups).order_by(Groups.id)
    return utils.paged_template(
        'grp_sel.html', _groups=groups, selected=set(session.pop('selected')))

@route('/grp/select', method='POST')
@utils.chklogin('admin')
def _select(session):
    session['selected'] = request.forms.getall('groups')
    return bottle.redirect(request.query.next or '/')

@route('/grp/add')
@utils.chklogin('admin')
def _add(session):
    return template('grp_edit.html', group=Groups(perms=''))

@route('/grp/add', method="POST")
@utils.chklogin('admin')
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
@utils.chklogin('admin')
def _edit(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'
    return template('grp_edit.html', group=group)

@route('/grp/<id:int>/edit', method='POST')
@utils.chklogin('admin')
def _edit(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'

    perms = set(request.forms.getall('perms')) & set(ALLPERMS)
    perms = ','.join(perms)
    group.perms = perms
    group.name = request.forms.name

    utils.log(logger, 'change group name %s => %s, perms: %s => %s' % (
        group.name, request.forms.name, group.perms, perms))
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/<id:int>/usrs')
@utils.chklogin('admin')
def _associated(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'
    grpusrs = set([u.username for u in group.users])

    if 'selected' not in session:
        session['selected'] = grpusrs
        return bottle.redirect('/usr/select?next=%s' % request.path)
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
@utils.chklogin('admin')
def _associated(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'
    grpaccts = set([a.id for a in group.accounts])

    if 'selected' not in session:
        session['selected'] = grpaccts
        return bottle.redirect('/acct/select?next=%s' % request.path)
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

@route('/grp/<id:int>/grp')
@utils.chklogin('admin')
def _associated(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'
    grpgrps = set([gg.parent.id for gg in group.parents])

    if 'selected' not in session:
        session['selected'] = grpgrps
        return bottle.redirect('/grp/select?next=%s' % request.path)
    groups = set(session.pop('selected'))

    # remove relationship which de-selected.
    rmset = grpgrps - groups
    rmset = [gg for gg in group.parents if gg.parent.id in rmset]
    map(group.parents.remove, rmset)
    map(sess.delete, rmset)

    for id in groups - grpgrps:
        grp = sess.query(Groups).filter_by(id=id).scalar()
        if not grp:
            sess.rollback()
            return 'group not exist.'
        if is_parent(grp, group):
            sess.rollback()
            return 'Oops, parents looped.'
        group.parents.append(GroupGroup(
            childid=group.id, parentid=id))

    utils.log(logger, 'associated group to group %s(%d): %s' % (
        group.name, group.id, ','.join([str(id) for id in groups])))
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/<id:int>/rem')
@utils.chklogin('admin')
def _remove(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'

    utils.log(logger, 'del group: %d %s' % (group.id, group.name))
    sess.delete(group)
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/cal')
@utils.chklogin('admin')
def _calculus(session):
    username = request.query.get('username')
    account = request.query.get('account')
    host = request.query.get('host')
    if not (username and account and host):
        return template('cal.html')

    user = sess.query(Users).filter_by(username=username).scalar()
    if not user:
        return template('cal.html', errmsg='user not found')
    acct = sess.query(Accounts).filter_by(account=account).join(Accounts.host).filter_by(host=host).scalar()
    if not acct:
        return template('cal.html', errmsg='account not found')

    perms = cal_group(user, acct)
    return template('cal.html', perms=perms)
