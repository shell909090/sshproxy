#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, logging
import bottle
from bottle import route, template, request

logger = logging.getLogger('records')
app = bottle.default_app()

@route('/rec/')
def _list():
    pass

@route('/rec/<rec:int>')
def _show(rec):
    pass

@route('/adt/')
def _list():
    pass

@route('/adt/<adt:int>')
def _show(audit):
    pass
