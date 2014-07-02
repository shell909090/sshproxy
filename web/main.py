#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, getopt, sqlite3
from bottle import run, default_app, route, static_file

app = default_app()
optlist, args = getopt.getopt(sys.argv[1:], 'a:c:hp:')
optdict = dict(optlist)

def init():
    app.config.load_config(optdict.get('-c', 'web.ini'))
    app.config['db.conn'] = sqlite3.connect(app.config['db.path'])
init()

@route('/static/<filename:path>')
def server_static(filename):
    return static_file(filename, root='static/')

import users

def main():
    if '-h' in optdict:
        print main.__doc__
        return

    host = optdict.get('-a', 'localhost')
    port = int(optdict.get('-p') or '8080')
    run(host=host, port=port, reloader=True)

if __name__ == '__main__': main()
else: application = app
