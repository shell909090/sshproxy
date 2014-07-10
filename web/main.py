#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, getopt, logging
import bottle
from beaker.middleware import SessionMiddleware
import sqlalchemy, sqlalchemy.orm

logger = logging.getLogger('main')
app = bottle.default_app()

optlist, args = getopt.getopt(sys.argv[1:], 'a:c:hp:')
optdict = dict(optlist)

app.config.load_config(optdict.get('-c', 'web.ini'))
engine = sqlalchemy.create_engine(app.config['db.url'])
sess = sqlalchemy.orm.sessionmaker(bind=engine)()
app.config['db.engine'] = engine
app.config['db.session'] = sess

import utils
utils.initlog(app.config.get('log.level', 'INFO'),
              app.config.get('log.logfile', ''))

session_opts = {
    'session.type': 'ext:database',
    'session.url': app.config['db.url'],
    'session.lock_dir': '/var/lock',
    'session.cookie_expires': 3600,
    'session.auto': True
}
application = SessionMiddleware(app, session_opts)

@bottle.route('/static/<filename:path>')
def _static(filename):
    return bottle.static_file(filename, root='static/')

import users, hosts, groups, records, local

def main():
    if '-h' in optdict:
        print main.__doc__
        return

    host = optdict.get('-a', 'localhost')
    port = int(optdict.get('-p') or '8080')
    bottle.run(app=application, host=host, port=port, reloader=True)

if __name__ == '__main__': main()
