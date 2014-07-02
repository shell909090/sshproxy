#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging
import bottle
from bottle import route, template, request

logger = logging.getLogger('users')
app = bottle.default_app()

@route('/h/')
def _list():
    pass

@route('/h/add')
def _add():
    pass

@route('/h/<host>/edit')
def _edit(host):
    pass

@route('/h/<host>/rem')
def _remove(host):
    pass

@route('/h/imp')
def _import():
    pass

@route('/h/acct/<host>/')
def _list(host):
    pass

@route('/h/acct/<host>/add')
def _add(host):
    pass

@route('/h/acct/<account:int>/edit')
def _edit(account):
    pass

@route('/h/acct/<account:int>/rem')
def _remove(account):
    pass
