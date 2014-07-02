#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys
from bottle import request, redirect

def chklogin(perm=None):
    def receiver(func):
        def _inner(*p, **kw):
            session = request.environ.get('beaker.session')
            if 'username' not in session:
                return redirect('/usr/login?next=%s' % request.path)
            return func(*p, **kw)
        return _inner
    return receiver
