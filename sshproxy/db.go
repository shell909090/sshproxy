package sshproxy

import (
	"database/sql"
	"time"
)

func (ci *ConnInfo) loadHost() (err error) {
	var ProxyCommand sql.NullString
	var ProxyAccount sql.NullInt64
	err = ci.srv.db.QueryRow("SELECT id, hostname, port, proxycommand, proxyaccount, hostkeys FROM hosts WHERE host=?", ci.Host).Scan(
		&ci.Hostid, &ci.Hostname, &ci.Port, &ProxyCommand, &ProxyAccount, &ci.Hostkeys)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	if ProxyCommand.Valid {
		ci.ProxyCommand = ProxyCommand.String
	}
	if ProxyAccount.Valid {
		ci.ProxyAccount = int(ProxyAccount.Int64)
	}
	return
}

func (ci *ConnInfo) insertRecord() (err error) {
	res, err := ci.srv.db.Exec("INSERT INTO records(username, account, host) values(?,?,?)",
		ci.Username, ci.Account, ci.Host)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	ci.RecordId, err = res.LastInsertId()
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) getStarttime() (starttime time.Time, err error) {
	err = ci.srv.db.QueryRow("SELECT starttime FROM records WHERE id=?",
		ci.RecordId).Scan(&starttime)
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) updateEndtime() (err error) {
	_, err = ci.srv.db.Exec("UPDATE records SET endtime=CURRENT_TIMESTAMP WHERE id=?",
		ci.RecordId)
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) insertRecordLogs(rltype, log1, log2 string, num1 int) (id int64, err error) {
	res, err := ci.srv.db.Exec("INSERT INTO recordlogs(recordid, type, log1, log2, num1) VALUES (?, ?, ?, ?, ?)", ci.RecordId, rltype, log1, log2, num1)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	id, err = res.LastInsertId()
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) getPrikey() (key string, err error) {
	err = ci.srv.db.QueryRow("SELECT key FROM accounts WHERE account=? AND hostid=?",
		ci.Account, ci.Hostid).Scan(&key)
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) getProxy(accountid int) (account, keys, hostname string, port int, hostkeys string, err error) {
	err = ci.srv.db.QueryRow("SELECT a.account, a.key, h.hostname, h.port, h.hostkeys FROM accounts a JOIN hosts h WHERE a.id=? AND a.hostid=h.id", accountid).Scan(
		&account, &keys, &hostname, &port, &hostkeys)
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}
