package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"encoding/base64"
	"time"
)

func (srv *Server) findPubkey(key ssh.PublicKey) (username string, err error) {
	pubkey := base64.StdEncoding.EncodeToString(key.Marshal())
	log.Debug("pubkey: %s", pubkey)
	err = srv.db.QueryRow("SELECT username FROM pubkeys WHERE pubkey=?",
		pubkey).Scan(&username)
	switch err {
	case sql.ErrNoRows:
		return "", ErrIllegalPubkey
	case nil:
	default:
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) loadHost() (err error) {
	var ProxyCommand sql.NullString
	var ProxyAccount sql.NullInt64
	err = ci.db.QueryRow("SELECT id, hostname, port, proxycommand, proxyaccount, hostkeys FROM hosts WHERE host=?", ci.Host).Scan(
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

func (ci *ConnInfo) loadAccount() (err error) {
	// load private key from user and host
	var Key sql.NullString
	var Password sql.NullString
	err = ci.db.QueryRow("SELECT id, key, password FROM accounts WHERE account=? AND hostid=?",
		ci.Account, ci.Hostid).Scan(&ci.Accountid, &Key, &Password)
	if err != nil {
		log.Error("%s", err.Error())
	}
	if Key.Valid {
		ci.Key = Key.String
	}
	if Password.Valid {
		ci.Password = Password.String
	}
	return
}

func (ci *ConnInfo) loadPerms() (err error) {
	v := url.Values{}
	v.Add("username", ci.Username)
	v.Add("account", ci.Account)
	v.Add("host", ci.Host)

	url := fmt.Sprintf("http://localhost:8080/perms?%s", v.Encode())
	log.Info("access %s", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Error("query perms failed: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("query perms failed: %s", err.Error())
		return
	}

	perms := strings.Split(string(b), ",")
	log.Info("query perms: %s / %s@%s => %s.", ci.Username, ci.Account, ci.Host, string(b))
	for _, p := range perms {
		ci.Perms[p] = 1
	}
	return
}

func (ci *ConnInfo) insertRecord() (err error) {
	res, err := ci.db.Exec("INSERT INTO records(username, account, host) values(?,?,?)",
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
	err = ci.db.QueryRow("SELECT starttime FROM records WHERE id=?",
		ci.RecordId).Scan(&starttime)
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) updateEndtime() (err error) {
	_, err = ci.db.Exec("UPDATE records SET endtime=CURRENT_TIMESTAMP WHERE id=?",
		ci.RecordId)
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (ci *ConnInfo) getProxy(accountid int) (account, Keys, Password, hostname string, port int, hostkeys string, err error) {
	var keys sql.NullString
	var password sql.NullString
	err = ci.db.QueryRow("SELECT a.account, a.key, a.password, h.hostname, h.port, h.hostkeys FROM accounts a JOIN hosts h WHERE a.id=? AND a.hostid=h.id", accountid).Scan(
		&account, &keys, &password, &hostname, &port, &hostkeys)
	if err != nil {
		log.Error("%s", err.Error())
	}
	if keys.Valid {
		Keys = keys.String
	}
	if password.Valid {
		Password = password.String
	}
	return
}

func (chi *ChanInfo) insertRecordLogs(rltype, log1, log2 string, num1 int) (id int64, err error) {
	res, err := chi.ci.db.Exec("INSERT INTO recordlogs(recordid, type, log1, log2, num1) VALUES (?, ?, ?, ?, ?)", chi.ci.RecordId, rltype, log1, log2, num1)
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
