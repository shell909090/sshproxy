#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-06-27
@author: shell.xu
'''
import os, sys, base64, getopt, sqlite3, subprocess

def main():
    optlist, args = getopt.getopt(sys.argv[1:], 'a:hp:')
    optdict = dict(optlist)
    if '-h' in optdict:
        print main.__doc__
        return

    host = args[1]
    port = int(optdict.get('-p') or '22')
    hostname = args[2]
    proxyaccount = int(optdict.get('-a') or '0')
    hostkeys = subprocess.check_output(["ssh-keyscan", "-t", "rsa,dsa,ecdsa", args[2]])

    conn = sqlite3.connect(args[0])
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO hosts(host, hostname, port, proxycommand, proxyaccount, hostkeys) VALUES (?, ?, ?, '', ?, ?)",
        (host, hostname, port, proxyaccount, hostkeys))
    conn.commit()

if __name__ == '__main__': main()
