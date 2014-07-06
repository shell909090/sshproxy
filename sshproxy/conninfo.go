package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type ConnInfo struct {
	srv *Server
	wg  sync.WaitGroup

	Username     string
	Account      string
	Hostid       int
	Host         string
	Hostname     string
	Port         int
	ProxyCommand string
	ProxyAccount int
	Hostkeys     string

	RecordId  int64
	Starttime time.Time

	Type      string
	ch_ready  chan int
	RemoteDir string

	chin  ssh.Channel
	chout ssh.Channel

	out io.WriteCloser
	in  io.WriteCloser
	cmd io.WriteCloser
}

func (srv *Server) createConnInfo(username, account, host string) (ci *ConnInfo, err error) {
	ci = &ConnInfo{
		srv:      srv,
		Username: username,
		Account:  account,
		Host:     host,
		ch_ready: make(chan int, 0),
	}

	var ProxyCommand sql.NullString
	var ProxyAccount sql.NullInt64
	err = srv.db.QueryRow("SELECT id, hostname, port, proxycommand, proxyaccount, hostkeys FROM hosts WHERE host=?", host).Scan(
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

	res, err := srv.db.Exec("INSERT INTO records(username, account, host) values(?,?,?)",
		ci.Username, ci.Account, ci.Host)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	ci.RecordId, err = res.LastInsertId()
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	err = ci.prepareFile()
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	return
}

func (ci *ConnInfo) prepareFile() (err error) {
	err = ci.srv.db.QueryRow("SELECT starttime FROM records WHERE id=?",
		ci.RecordId).Scan(&ci.Starttime)
	if err != nil {
		return
	}

	logDir := fmt.Sprintf("%s/%s", ci.srv.LogDir, ci.Starttime.Format("20060102"))
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		return
	}

	ci.out, err = os.OpenFile(fmt.Sprintf("%s/%d.out", logDir, ci.RecordId),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return
	}

	ci.in, err = os.OpenFile(fmt.Sprintf("%s/%d.in", logDir, ci.RecordId),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	return
}

func (ci *ConnInfo) Close() (err error) {
	_, err = ci.srv.db.Exec("UPDATE records SET endtime=CURRENT_TIMESTAMP WHERE id=?",
		ci.RecordId)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	return
}

func (ci *ConnInfo) onFileTransmit(filename string, size int) {
	log.Notice("%s with name: %s, size: %d, remote dir: %s",
		ci.Type, filename, size, ci.RemoteDir)

	_, err := ci.srv.db.Exec("INSERT INTO recordlogs(recordid, type, filename, size, remotedir) VALUES (?, ?, ?, ?, ?)", ci.RecordId, ci.Type, filename, size, ci.RemoteDir)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	return
}

func (ci *ConnInfo) onChanReq(req *ssh.Request) (err error) {
	var strs []string
	switch req.Type {
	case "env":
		strs, err = ReadPayloads(req.Payload)
		if err != nil {
			return
		}
		for _, env := range strs {
			log.Debug("env: %s", env)
		}
	case "exec":
		strs, err = ReadPayloads(req.Payload)
		if err != nil {
			return
		}

		log.Debug("exec with cmd: %s.", strs[0])
		cmds := strings.Split(strs[0], " ")

		if cmds[0] == "scp" {
			switch cmds[len(cmds)-2] {
			case "-t":
				ci.Type = "scpto"
			case "-f":
				ci.Type = "scpfrom"
			}
			ci.RemoteDir = cmds[len(cmds)-1]
			log.Info("session in %s mode, remote dir: %s.",
				ci.Type, ci.RemoteDir)
			ci.ch_ready <- 1
		}
	case "shell":
		ci.Type = "shell"
		log.Info("session in shell mode")
		ci.ch_ready <- 1
	case "x11-req":
		strs, err = ReadPayloads(req.Payload[1:])
		if err != nil {
			return
		}
		for _, env := range strs {
			log.Debug("x11: %s", env)
		}
	case "pty-req", "keepalive@openssh.com", "auth-agent-req@openssh.com":
	default:
		log.Debug("%v", req.Payload)
	}
	return nil
}
