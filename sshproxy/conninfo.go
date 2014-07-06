package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
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

	RecordId int64

	Type      string
	ch_ready  chan int
	RemoteDir string
}

func (srv *Server) createConnInfo(username, account, host string) (ci *ConnInfo, err error) {
	ci = &ConnInfo{
		srv:      srv,
		Username: username,
		Account:  account,
		Host:     host,
		ch_ready: make(chan int, 0),
	}

	err = ci.loadHost()
	if err != nil {
		return
	}

	err = ci.insertRecord()
	return
}

func (ci *ConnInfo) Close() (err error) {
	return ci.updateEndtime()
}

func (ci *ConnInfo) prepareFile(ext string) (w io.WriteCloser, err error) {
	starttime, err := ci.getStarttime()
	if err != nil {
		return
	}

	logDir := fmt.Sprintf("%s/%s", ci.srv.LogDir, starttime.Format("20060102"))
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		return
	}

	RecordLogsId, err := ci.insertRecordLogs(ci.Type, "", "", 0, "", 0, "")
	if err != nil {
		return
	}

	w, err = os.OpenFile(fmt.Sprintf("%s/%d.%s", logDir, RecordLogsId, ext),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	return
}

func (ci *ConnInfo) onFileTransmit(filename string, size int) (err error) {
	log.Notice("%s with name: %s, size: %d, remote dir: %s",
		ci.Type, filename, size, ci.RemoteDir)
	_, err = ci.insertRecordLogs(ci.Type, "", "", 0, filename, size, ci.RemoteDir)
	return
}

func (ci *ConnInfo) onTcpForward(direct, ip string, port uint32) (err error) {
	log.Notice("mapping %s port to %s:%d", direct, ip, port)
	_, err = ci.insertRecordLogs(ci.Type, "", ip, int(port), "", 0, "")
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

func (ci *ConnInfo) onChanType(chantype string, extra []byte) (err error) {
	switch chantype {
	case "session":
	case "direct-tcpip":
		ci.Type = "local"
		ci.ch_ready <- 1

		ip, port, _, _, err := getTcpInfo(extra)
		if err != nil {
			return err
		}

		err = ci.onTcpForward("local", ip, port)
		if err != nil {
			return err
		}
	case "forwarded-tcpip":
		ci.Type = "remote"
		ci.ch_ready <- 1

		ip, port, _, _, err := getTcpInfo(extra)
		if err != nil {
			return err
		}

		err = ci.onTcpForward("remote", ip, port)
		if err != nil {
			return err
		}
	case "auth-agent@openssh.com":
		ci.Type = "sshagent"
		ci.ch_ready <- 1
	default:
		log.Error("channel type %s not supported.", chantype)
		err = ErrChanTypeNotSupported
	}
	return
}
