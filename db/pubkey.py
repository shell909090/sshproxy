#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-06-27
@author: shell.xu
'''
import os, sys, sqlite3

def main():
    username = sys.argv[2]
    conn = sqlite3.connect(sys.argv[1])
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO users(realname, password, perms) VALUES (?, ?, ?)",
              (username, "123", 'admin,users,hosts,accounts,records,audit'))
    for line in sys.stdin:
        pubkey, name = line.strip().split()[1:]
        pubkey = pubkey.replace('\r', '').replace('\n', '')
        c.execute("INSERT INTO user_pubkey(name, realname, pubkey) VALUES (?, ?, ?)",
                  (name, username, pubkey))
    conn.commit()

if __name__ == '__main__': main()
