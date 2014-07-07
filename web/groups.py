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
    return paged_template('grp.html', _groups=groups)

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

    perms = set(request.forms.getall('perms')) & set(ALLPERMS)
    perms = ','.join(perms)
    utils.log(logger, 'change group name %s => %s, perms: %s => %s' % (
        group.name, name, group.perms, perms))
    group.name = name
    group.perms = perms
    sess.commit()
    return bottle.redirect('/grp/')

@route('/grp/<id:int>/rem')
@utils.chklogin('groups')
def _remove(session, id):
    group = sess.query(Groups).filter_by(id=id).scalar()
    if not group:
        return 'group not exist.'

    utils.log(logger, 'del group: %d %s' % (group.id, group.name))
    sess.delete(acct)
    sess.commit()
    return bottle.redirect('/grp/')
