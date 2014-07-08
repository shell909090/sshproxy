#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging, tempfile, subprocess
import bottle, utils
from bottle import route, template, request
from db import *

logger = logging.getLogger('hosts')
app = bottle.default_app()
sess = app.config['db.session']

@route('/h/')
@utils.chklogin()
def _list(session):
    hosts = sess.query(Hosts)
    q = request.query.q
    if q:
        hosts = hosts.filter(or_(
                Hosts.host.like('%'+q+'%'),
                Hosts.hostname.like('%'+q+'%')))
    hosts = hosts.order_by(Hosts.id)
    return utils.paged_template('hosts.html', _hosts=hosts)

@route('/h/add')
@utils.chklogin('hosts')
def _add(session):
    return template('hosts_edit.html', host=Hosts())

@route('/h/add', method='POST')
@utils.chklogin('hosts')
def _add(session):
    h = request.forms.get('host')
    host = sess.query(Hosts).filter_by(host=h).scalar()
    if host:
        return template('hosts_edit.html', host=Hosts(), errmsg='host exist.')

    if request.forms.get('proxycommand') and not request.forms.get('proxyaccount'):
        return template(
            'hosts_edit.html', host=Hosts(),
            errmsg="proxy command can't use without proxyaccount.")

    utils.log(logger, 'add host: %s' % h)
    host = Hosts(
        host=request.forms.get('host'),
        hostname=request.forms.get('hostname'),
        port=int(request.forms.get('port')),
        hostkeys='')
    sess.add(host)

    if request.forms.get('proxycommand'):
        host.proxycommand = request.forms.get('proxycommand')
    if request.forms.get('proxyaccount'):
        a, h = request.forms.get('proxyaccount').split('@', 1)
        host.proxy = sess.query(Accounts).filter_by(account=a).join(Accounts.host).filter_by(host=h).scalar()

    sess.commit()
    return bottle.redirect('/h/')

@route('/h/<id:int>/edit')
@utils.chklogin('hosts')
def _edit(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return 'host not exist.'
    return template('hosts_edit.html', host=host)

@route('/h/<id:int>/edit', method='POST')
@utils.chklogin('hosts')
def _edit(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return template('hosts_edit.html', host=Hosts(), errmsg='host not exist.')

    if request.forms.get('proxycommand') and not request.forms.get('proxyaccount'):
        return template(
            'hosts_edit.html', host=Hosts(),
            errmsg="proxy command can't use without proxyaccount.")

    utils.log(logger, 'edit host: %s' % host.host)
    host.host = request.forms.get('host')
    host.hostname = request.forms.get('hostname')
    host.port = int(request.forms.get('port'))
    host.proxycommand = request.forms.get('proxycommand')

    if request.forms.get('proxyaccount'):
        a, h = request.forms.get('proxyaccount').split('@', 1)
        host.proxy = sess.query(Accounts).filter_by(account=a).join(Accounts.host).filter_by(host=h).scalar()
    else: host.proxy = None

    sess.commit()
    return bottle.redirect('/h/')

@route('/h/<id:int>/rem')
@utils.chklogin('hosts')
def _remove(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return 'host not exists.'
    utils.log(logger, 'delete host: %s' % host.host)
    sess.delete(host)
    sess.commit()
    return bottle.redirect('/h/')

@route('/h/<id:int>/renew')
@utils.chklogin('hosts')
def _renew_hostkey(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return 'host not exists.'
    hostkeys = subprocess.check_output(["ssh-keyscan", "-t", "rsa,dsa,ecdsa", host.hostname])
    with tempfile.NamedTemporaryFile(prefix='sshproxy') as fo:
        fo.write(hostkeys)
        fo.flush()
        fps = subprocess.check_output(["ssh-keygen", "-lf", fo.name])
    return template('hosts_key.html', hostkeys=hostkeys, fps=fps)

@route('/h/<id:int>/renew', method='POST')
@utils.chklogin('hosts')
def _renew_hostkey(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return 'host not exists.'
    hostkeys = request.forms.get('hostkey')
    utils.log(logger, 'renew hostkey: %s' % host.host)
    host.hostkeys = hostkeys
    sess.commit()
    return bottle.redirect('/h/')

@route('/acct/select')
@utils.chklogin('hosts')
def _select(session):
    accounts = session.pop('selected')
    hosts = sess.query(Hosts).order_by(Hosts.id)
    return utils.paged_template('acct_sel.html', _hosts=hosts, selected=accounts)

@route('/acct/select', method='POST')
@utils.chklogin('hosts')
def _select(session):
    accounts = request.forms.getall('accts')
    session['selected'] = accounts
    return bottle.redirect(request.query.next or '/')

@route('/acct/<id:int>')
@utils.chklogin('hosts')
def _list(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return 'host not exist.'
    accounts = sess.query(Accounts).filter_by(hostid=id)
    return template('acct.html', accounts=accounts, host=host)

@route('/acct/<id:int>/add')
@utils.chklogin('hosts')
def _add(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return 'host not exist.'
    return template('acct_edit.html', acct=Accounts(hostid=id), host=host)

@route('/acct/<id:int>/add', method='POST')
@utils.chklogin('hosts')
def _add(session, id):
    host = sess.query(Hosts).filter_by(id=id).scalar()
    if not host:
        return 'host not exist.'

    account = request.forms.get('account')
    acct = sess.query(Accounts).filter_by(account=account, host=host).scalar()
    if acct:
        return template(
            'acct_edit.html', acct=Accounts(hostid=id), host=host,
            errmsg='account exist.')

    utils.log(logger, 'add account: %s' % account)
    acct = Accounts(
        account=account, host=host,
        key=request.forms.get('key'))
    sess.add(acct)

    sess.commit()
    return bottle.redirect('/acct/%d' % id)

@route('/acct/<id:int>/edit')
@utils.chklogin('hosts')
def _edit(session, id):
    acct = sess.query(Accounts).filter_by(id=id).scalar()
    if not acct:
        return 'acct not exist.'
    return template('acct_edit.html', acct=acct, host=acct.host)

@route('/acct/<id:int>/edit', method='POST')
@utils.chklogin('hosts')
def _edit(session, id):
    acct = sess.query(Accounts).filter_by(id=id).scalar()
    if not acct:
        return 'acct not exist.'

    utils.log(logger, 'edit account: %s@%s' % (acct.account, acct.host.host))
    if request.forms.get('account'):
        acct.account = request.forms.get('account')
    if request.forms.get('key'):
        acct.key = request.forms.get('key')
    sess.commit()
    return bottle.redirect('/acct/%d' % int(acct.hostid))

@route('/acct/<id:int>/rem')
@utils.chklogin('hosts')
def _remove(session, id):
    acct = sess.query(Accounts).filter_by(id=id).scalar()
    if not acct:
        return 'acct not exist.'

    utils.log(logger, 'del account: %s@%s' % (acct.account, acct.host.host))
    sess.delete(acct)
    sess.commit()
    return bottle.redirect('/acct/%d' % int(acct.hostid))
