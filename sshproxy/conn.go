package sshproxy

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sync"
	"text/template"
	"time"
)

type ConnInfo struct {
	srv *Server
	db  *sql.DB
	wg  sync.WaitGroup

	Username string

	Host         string
	Account      string
	Acct         *AccountInfo
	Proxy        *AccountInfo
	ProxyCommand string

	Perms map[string]int

	RecordId  int
	Starttime time.Time
}

func (srv *Server) createSshConnServer(username, account, host string) (scs SshConnServer, err error) {
	ci := &ConnInfo{
		srv:      srv,
		Username: username,
		Account:  account,
		Host:     host,
		Perms:    make(map[string]int, 0),
	}

	err = ci.loadAccount()
	if err != nil {
		return
	}

	err = ci.insertRecord()
	if err != nil {
		return
	}

	return ci, nil
}

func (ci *ConnInfo) loadAccount() (err error) {
	v := &url.Values{}
	v.Add("username", ci.Username)
	v.Add("account", ci.Account)
	v.Add("host", ci.Host)

	type AccountRsltProxy struct {
		AccountInfo
		Proxy        *AccountInfo
		ProxyCommand string
		Perms        []string
	}
	rslt := &AccountRsltProxy{}

	err = ci.srv.GetJson("/h/query", false, v, rslt)
	if err != nil {
		return
	}

	ci.Acct = &rslt.AccountInfo
	if rslt.Proxy != nil {
		ci.Proxy = rslt.Proxy
		ci.ProxyCommand = rslt.ProxyCommand
	}

	log.Info("query perms: %s / %s@%s => %v.", ci.Username, ci.Account, ci.Host, rslt.Perms)
	for _, p := range rslt.Perms {
		ci.Perms[p] = 1
	}
	return
}

func (ci *ConnInfo) ChkPerm(name string) (ok bool) {
	_, ok = ci.Perms[name]
	return
}

func (ci *ConnInfo) insertRecord() (err error) {
	v := &url.Values{}
	v.Add("username", ci.Username)
	v.Add("account", ci.Account)
	v.Add("host", ci.Host)

	type RecordRslt struct {
		Recordid  int
		Starttime string
	}
	rslt := &RecordRslt{}

	err = ci.srv.GetJson("/rec/add", true, v, rslt)
	if err != nil {
		return
	}
	ci.RecordId = rslt.Recordid
	ci.Starttime, err = time.Parse("2006-01-02T15:04:05", rslt.Starttime)
	if err != nil {
		return
	}
	return
}

func (ci *ConnInfo) clientBuilder() (client ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, err error) {
	// and try connect it as last step
	hostname := fmt.Sprintf("%s:%d", ci.Acct.Hostname, ci.Acct.Port)
	var conn net.Conn
	switch {
	case ci.Proxy != nil:
		log.Info("ssh proxy: %s:%d with proxy %s@%s:%d",
			ci.Acct.Hostname, ci.Acct.Port,
			ci.Proxy.Account, ci.Proxy.Hostname, ci.Proxy.Port)
		conn, err = ci.connectProxy(ci.Acct.Hostname, ci.Acct.Port)
		if err != nil {
			log.Error("ssh dial failed: %s", err.Error())
			return
		}
	default:
		log.Info("dail: %s", hostname)
		conn, err = net.Dial("tcp", hostname)
		if err != nil {
			log.Error("tcp dial failed: %s", err.Error())
			return
		}
	}

	config, err := ci.Acct.ClientConfig()
	if err != nil {
		return
	}
	client, chans, reqs, err = ssh.NewClientConn(conn, hostname, config)
	if err != nil {
		log.Error("ssh client conn failed: %s", err.Error())
		return
	}
	return
}

func (ci *ConnInfo) getNet(client *ssh.Client, cmd string) (pn *PipeNet, err error) {
	session, err := client.NewSession()
	if err != nil {
		return
	}

	pn = &PipeNet{
		wa:   session,
		c:    client,
		name: "ssh",
	}

	pn.w, err = session.StdinPipe()
	if err != nil {
		return
	}
	pn.r, err = session.StdoutPipe()
	if err != nil {
		return
	}

	err = session.Start(cmd)
	return
}

func (ci *ConnInfo) fmtCmd(desthost string, destport int) (cmd string, err error) {
	if ci.ProxyCommand != "" {
		tmpl, err := template.New("test").Parse(ci.ProxyCommand)
		if err != nil {
			return "", err
		}

		parameter := map[string]interface{}{
			"host": desthost,
			"port": destport,
		}

		buf := bytes.NewBuffer(nil)
		err = tmpl.Execute(buf, parameter)
		if err != nil {
			return "", err
		}
		cmd = buf.String()
	} else {
		cmd = fmt.Sprintf("nc %s %d", desthost, destport)
	}
	return
}

func (ci *ConnInfo) connectProxy(desthost string, destport int) (conn net.Conn, err error) {
	config, err := ci.Proxy.ClientConfig()
	if err != nil {
		return
	}

	log.Info("ssh to %s@%s:%d", ci.Proxy.Account, ci.Proxy.Hostname, ci.Proxy.Port)
	client, err := ssh.Dial("tcp",
		fmt.Sprintf("%s:%d", ci.Proxy.Hostname, ci.Proxy.Port), config)
	if err != nil {
		return
	}

	cmd, err := ci.fmtCmd(desthost, destport)
	if err != nil {
		return
	}
	log.Debug("cmd: %s", cmd)

	conn, err = ci.getNet(client, cmd)
	return
}

func (ci *ConnInfo) serveReq(conn ssh.Conn, req *ssh.Request) (err error) {
	r, b, err := conn.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		log.Error("%s", err.Error())
		req.Reply(false, nil)
		return err
	}
	log.Debug("send req ok: %s(result: %t)(payload: %d)", req.Type, r, len(b))

	err = req.Reply(r, b)
	if err != nil {
		return err
	}
	log.Debug("reply req ok: %s(result: %t)", req.Type, r)
	return
}

func (ci *ConnInfo) serveReqs(conn ssh.Conn, reqs <-chan *ssh.Request) (err error) {
	defer ci.wg.Done()
	log.Debug("reqs begin.")
	for req := range reqs {
		log.Debug("new req: %s(reply: %t, payload: %d).",
			req.Type, req.WantReply, len(req.Payload))
		err = ci.serveReq(conn, req)
		if err != nil {
			log.Error("%s", err.Error())
		}
	}
	log.Debug("reqs end.")
	return
}

func (ci *ConnInfo) serveChans(conn ssh.Conn, chans <-chan ssh.NewChannel) (err error) {
	defer ci.wg.Done()
	defer conn.Close()
	log.Debug("chans begin.")
	for newChan := range chans {
		chi := CreateChanInfo(ci)
		err = chi.Serve(conn, newChan)
		if err != nil {
			log.Error("%s", err.Error())
		}
	}
	log.Debug("chans ends.")
	return
}

func (ci *ConnInfo) Serve(srvConn ssh.ServerConn, srvChans <-chan ssh.NewChannel, srvReqs <-chan *ssh.Request) (err error) {
	cliConn, cliChans, cliReqs, err := ci.clientBuilder()
	if err != nil {
		return
	}
	defer cliConn.Close()

	log.Debug("handshake ok")

	ci.wg.Add(4)
	go ci.serveReqs(cliConn, srvReqs)
	go ci.serveReqs(srvConn, cliReqs)
	go ci.serveChans(cliConn, srvChans)
	go ci.serveChans(srvConn, cliChans)
	ci.wg.Wait()

	log.Info("Connect closed.")
	return ci.updateEndtime()
}

func (ci *ConnInfo) updateEndtime() (err error) {
	v := &url.Values{}
	v.Add("recordid", fmt.Sprintf("%d", ci.RecordId))
	return ci.srv.GetJson("/rec/end", true, v, nil)
}
