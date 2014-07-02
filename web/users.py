#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys
from bottle import default_app, route, template, request

app = default_app()

@route('/users/login')
def login():
    return template('login.html')

@route('/users/login', method='POST')
def login():
    username = request.forms.get('username')
    password = request.forms.get('password')
    print username, password
    return template('login.html')

@route('/users/list')
def lists():
    conn = app.config['db.conn']
    cur = conn.cursor()
    for row in cur.execute('SELECT * FROM users'):
        print row
    return ""
