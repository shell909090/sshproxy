CREATE TABLE users (
       realname TEXT PRIMARY KEY,
       password TEXT
);

CREATE TABLE user_pubkey (
       realname TEXT REFERENCES users(realname),
       pubkey TEXT
);

CREATE TABLE hosts (
       'host' TEXT PRIMARY KEY,
       hostname TEXT,
       port INTEGER,
       proxycommand TEXT,
       hostkeys TEXT
);

CREATE TABLE accounts (
       username TEXT,
       'host' TEXT REFERENCES hosts('host'),
       keys TEXT
);

CREATE TABLE perms (
       realname TEXT REFERENCES users(realname),
       username TEXT,
       'host' TEXT REFERENCES hosts('host'),
       perm INTEGER
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
