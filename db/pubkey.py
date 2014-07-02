#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-06-27
@author: shell.xu
'''
import os, sys, base64, sqlite3

def main():
    username = sys.argv[2]
    conn = sqlite3.connect(sys.argv[1])
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO users(realname, password) VALUES (?, ?)", (username, "123"))
    for line in sys.stdin:
        pubkey, name = line.strip().split()[1:]
        pubkey = base64.b64decode(pubkey)
        c.execute("INSERT INTO user_pubkey(name, realname, pubkey) VALUES (?, ?, ?)", (name, username, pubkey))
        print (name, username, pubkey)
    conn.commit()

    for row in c.execute('select * from user_pubkey').fetchall():
        print row

if __name__ == '__main__': main()
