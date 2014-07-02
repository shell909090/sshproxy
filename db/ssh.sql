CREATE TABLE users (
       realname TEXT PRIMARY KEY,
       password TEXT
);

CREATE TABLE user_pubkey (
       id INTEGER PRIMARY KEY,
       'name' TEXT,
       realname TEXT REFERENCES users(realname),
       pubkey TEXT
);

CREATE INDEX IF NOT EXISTS user_pubkey_pubkey ON user_pubkey (
       pubkey
);

CREATE TABLE hosts (
       'host' TEXT PRIMARY KEY,
       hostname TEXT,
       port INTEGER,
       proxycommand TEXT,
       proxyaccount INTEGER REFERENCES accounts(id),
       hostkeys TEXT
);

CREATE TABLE accounts (
       id INTEGER PRIMARY KEY,
       username TEXT,
       'host' TEXT REFERENCES hosts('host'),
       keys TEXT
);

CREATE INDEX IF NOT EXISTS accounts_username_host ON accounts (
       username,
       'host'
);

CREATE TABLE perms (
       realname TEXT REFERENCES users(realname),
       username TEXT,
       'host' TEXT REFERENCES hosts('host'),
       perm TEXT
);

CREATE TABLE records (
       id INTEGER PRIMARY KEY,
       realname TEXT REFERENCES users(realname),
       username TEXT,
       'host' TEXT REFERENCES hosts('host'),
       starttime TEXT DEFAULT CURRENT_TIMESTAMP,
       endtime TEXT
);

CREATE TABLE record_files (
       id INTEGER PRIMARY KEY,
       recordid INTEGER REFERENCES records(id),
       'type' TEXT,
       filename TEXT,
       'size' INTEGER,
       remotedir TEXT
);

CREATE TABLE auditlog (
       id INTEGER PRIMARY KEY,
       'time' TEXT DEFAULT CURRENT_TIMESTAMP,
       realname TEXT REFERENCES users(realname),
       'level' INTEGER,
       log TEXT
);
