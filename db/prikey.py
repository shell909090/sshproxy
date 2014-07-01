#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2014-06-27
@author: shell.xu
'''
import os, sys, sqlite3
from os import path

def main():
    username, host = sys.argv[2].split('@')
    prikey = sys.stdin.read()

    conn = sqlite3.connect(sys.argv[1])
    c = conn.cursor()
    c.execute(
        "INSERT INTO accounts(username, host, keys) VALUES (?, ?, ?)",
        (username, host, prikey))
    conn.commit()

if __name__ == '__main__': main()
