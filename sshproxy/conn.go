package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"
)

type ConnInfo struct {
	srv  *Server
	wg   sync.WaitGroup
	conn ssh.Conn

	Username string
	Host     string
	Account  string

	Acct         *AccountInfo
	Proxy        *AccountInfo
	ProxyCommand string
	Perms        map[string]int

	RecordId  int
	Starttime time.Time
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

	err = ci.srv.GetJson("/l/h", false, v, rslt)
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
	if len(ci.Perms) == 0 {
		err = ErrNoPerms
		log.Error("%s", err.Error())
		return
	}
	return
}

func (ci *ConnInfo) Close() (err error) {
	return ci.conn.Close()
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

	err = ci.srv.GetJson("/l/rec", true, v, rslt)
	if err != nil {
		return
	}
	ci.RecordId = rslt.Recordid
	ci.Starttime, err = time.Parse("2006-01-02T15:04:05", rslt.Starttime)
	if err != nil {
		log.Error("%s", err.Error())
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

	cmd, err := fmtCmd(ci.ProxyCommand, desthost, destport)
	if err != nil {
		return
	}
	log.Debug("cmd: %s", cmd)

	return createPipeNet(client, cmd)
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

func (ci *ConnInfo) Serve(srvConn *ssh.ServerConn, srvChans <-chan ssh.NewChannel, srvReqs <-chan *ssh.Request) (err error) {
	conn, cliChans, cliReqs, err := ci.clientBuilder()
	if err != nil {
		return
	}
	defer conn.Close()
	ci.conn = conn

	log.Debug("handshake ok")

	ci.wg.Add(4)
	go ci.serveReqs(ci.conn, srvReqs)
	go ci.serveReqs(srvConn, cliReqs)
	go ci.serveChans(ci.conn, srvChans)
	go ci.serveChans(srvConn, cliChans)
	ci.wg.Wait()

	log.Info("connect closed.")
	return ci.updateEndtime()
}

func (ci *ConnInfo) updateEndtime() (err error) {
	v := &url.Values{}
	v.Add("recordid", fmt.Sprintf("%d", ci.RecordId))
	return ci.srv.GetJson("/l/end", true, v, nil)
}
