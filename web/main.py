#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-07-02
@author: shell.xu
'''
import os, sys, getopt, sqlite3, logging
import bottle
from beaker.middleware import SessionMiddleware

LOGFMT = '%(asctime)s.%(msecs)03d[%(levelname)s](%(module)s:%(lineno)d): %(message)s'
def initlog(lv, logfile=None, stream=None, longdate=False):
    if isinstance(lv, basestring): lv = getattr(logging, lv)
    kw = {'format': LOGFMT, 'datefmt': '%H:%M:%S', 'level': lv}
    if logfile: kw['filename'] = logfile
    if stream: kw['stream'] = stream
    if longdate: kw['datefmt'] = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(**kw)

logger = logging.getLogger('main')
app = bottle.default_app()
optlist, args = getopt.getopt(sys.argv[1:], 'a:c:hp:')
optdict = dict(optlist)

def init():
    app.config.load_config(optdict.get('-c', 'web.ini'))
    app.config['db.conn'] = sqlite3.connect(app.config['db.path'])
    initlog(app.config.get('log.level', 'INFO'),
            app.config.get('log.logfile', ''))
init()

@bottle.route('/static/<filename:path>')
def server_static(filename):
    return bottle.static_file(filename, root='static/')

import users, hosts, records

session_opts = {
    'session.type': 'memory',
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
