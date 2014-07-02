#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, getopt, sqlite3, logging
import bottle, utils
from beaker.middleware import SessionMiddleware
import sqlalchemy, sqlalchemy.orm

logger = logging.getLogger('main')
app = bottle.default_app()
optlist, args = getopt.getopt(sys.argv[1:], 'a:c:hp:')
optdict = dict(optlist)

def init():
    app.config.load_config(optdict.get('-c', 'web.ini'))
    app.config['db.engine'] = sqlalchemy.create_engine(app.config['db.url'])
    app.config['db.session'] = sqlalchemy.orm.sessionmaker(bind=app.config['db.engine'])()
    utils.initlog(app.config.get('log.level', 'INFO'),
                  app.config.get('log.logfile', ''))
init()

@bottle.route('/static/<filename:path>')
def server_static(filename):
    return bottle.static_file(filename, root='static/')

import users, hosts, records

session_opts = {
    'session.type': 'ext:database',
    'session.url': 'sqlite:///../ssh.db',
    'session.lock_dir': '/var/lock',
    'session.cookie_expires': 300,
    'session.auto': True
}
application = SessionMiddleware(app, session_opts)

def main():
    if '-h' in optdict:
        print main.__doc__
        return

    host = optdict.get('-a', 'localhost')
    port = int(optdict.get('-p') or '8080')
    bottle.run(app=application, host=host, port=port, reloader=True)

if __name__ == '__main__': main()
