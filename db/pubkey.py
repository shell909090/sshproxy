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
    c.execute("INSERT OR REPLACE INTO users VALUES (?, ?)", (username, ""))
    for line in sys.stdin:
        pubkey = base64.b64decode(line.strip().split()[1])
        c.execute("INSERT INTO user_pubkey VALUES (?, ?)", (username, pubkey))
    conn.commit()

if __name__ == '__main__': main()
