package sshproxy

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"text/template"
)

func CheckHostKey(HostKey string) (checkHostKey func(string, net.Addr, ssh.PublicKey) error) {
	var err error
	var public ssh.PublicKey
	var publices []ssh.PublicKey
	rest := []byte(HostKey)
	for {
		public, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			err = nil
			break
		}
		publices = append(publices, public)
	}

	checkHostKey = func(hostname string, remote net.Addr, key ssh.PublicKey) (err error) {
		hostkey := key.Marshal()
		log.Debug("remote hostkey: %s, type: %s", hostname, key.Type())

		for _, public := range publices {
			if key.Type() == public.Type() && bytes.Compare(hostkey, public.Marshal()) == 0 {
				log.Info("host key match: %s", hostname)
				return nil
			}
		}
		log.Info("host key not match: %s", hostname)
		return ErrHostKey
	}
	return
}

func genClientConfig(Account, PrivateKey, HostKey string) (config *ssh.ClientConfig, err error) {
	private, err := ssh.ParsePrivateKey([]byte(PrivateKey))
	if err != nil {
		log.Error("failed to parse keyfile: %s", err.Error())
		return
	}

	config = &ssh.ClientConfig{
		User:            Account,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(private)},
		HostKeyCallback: CheckHostKey(HostKey),
	}
	return
}

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
	RecordId     int64
}

func (srv *Server) createConnProcesser(username, account, host string) (cp ConnProcesser, err error) {
	ci := &ConnInfo{
		srv:      srv,
		Username: username,
		Account:  account,
		Host:     host,
	}

	err = ci.loadHost()
	if err != nil {
		return
	}

	err = ci.insertRecord()
	if err != nil {
		return
	}

	return ci, nil
}

func (ci *ConnInfo) Close() (err error) {
	return ci.updateEndtime()
}

func (ci *ConnInfo) clientBuilder() (client ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, err error) {
	// load private key from user and host
	key, err := ci.getPrikey()
	if err != nil {
		return
	}

	// and try connect it as last step
	hostname := fmt.Sprintf("%s:%d", ci.Hostname, ci.Port)
	var conn net.Conn
	switch {
	case ci.ProxyAccount != 0:
		log.Info("ssh proxy: %s:%d with accountid %d",
			ci.Hostname, ci.Port, ci.ProxyAccount)
		conn, err = ci.ConnAccount(ci.ProxyAccount, ci.Hostname, ci.Port)
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

	config, err := genClientConfig(ci.Account, key, ci.Hostkeys)
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

func (ci *ConnInfo) ConnAccount(accountid int, desthost string, destport int) (conn net.Conn, err error) {
	account, keys, hostname, port, hostkeys, err := ci.getProxy(accountid)
	if err != nil {
		return
	}
	log.Info("ssh to %s@%s:%d", account, hostname, port)

	config, err := genClientConfig(account, keys, hostkeys)
	if err != nil {
		return
	}

	hostname = fmt.Sprintf("%s:%d", hostname, port)
	client, err := ssh.Dial("tcp", hostname, config)
	if err != nil {
		return
	}

	session, err := client.NewSession()
	if err != nil {
		return
	}

	cn := &CmdNet{
		w:    session,
		c:    client,
		name: "ssh",
	}
	cn.stdin, err = session.StdinPipe()
	if err != nil {
		return
	}
	cn.stdout, err = session.StdoutPipe()
	if err != nil {
		return
	}

	var cmd string
	if ci.ProxyCommand != "" {
		tmpl, err := template.New("test").Parse(ci.ProxyCommand)
		if err != nil {
			return nil, err
		}

		parameter := map[string]interface{}{
			"host": desthost,
			"port": destport,
		}

		buf := bytes.NewBuffer(nil)
		err = tmpl.Execute(buf, parameter)
		if err != nil {
			return nil, err
		}
		cmd = buf.String()
	} else {
		cmd = fmt.Sprintf("nc %s %d", desthost, destport)
	}

	log.Debug("cmd: %s", cmd)
	err = session.Start(cmd)
	if err != nil {
		return
	}

	return cn, nil
}

func (ci *ConnInfo) serveReq(conn ssh.Conn, req *ssh.Request) (err error) {
	if req.Type == "tcpip-forward" {
		fmt.Sprintf("%v", req.Payload)
	}

	r, b, err := conn.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
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
			return err
		}
	}
	log.Debug("reqs end.")
	return
}

func (ci *ConnInfo) serveChans(conn ssh.Conn, chans <-chan ssh.NewChannel) (err error) {
	defer ci.wg.Done()
	log.Debug("chans begin.")
	for newChan := range chans {
		chi := CreateChanInfo(ci)
		err = chi.Serve(conn, newChan)
		if err != nil {
			log.Error("%s", err.Error())
			return
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
	return
}
