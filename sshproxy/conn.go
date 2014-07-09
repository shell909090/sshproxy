package sshproxy

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
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

func genClientConfig(HostKey, Account, PrivateKey, Password string) (config *ssh.ClientConfig, err error) {
	config = &ssh.ClientConfig{
		User:            Account,
		HostKeyCallback: CheckHostKey(HostKey),
	}

	if PrivateKey != "" {
		private, err := ssh.ParsePrivateKey([]byte(PrivateKey))
		if err != nil {
			log.Error("failed to parse keyfile: %s", err.Error())
			return nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(private))
	}
	if Password != "" {
		config.Auth = append(config.Auth, ssh.Password(Password))
	}

	return
}

type ConnInfo struct {
	srv *Server
	db  *sql.DB
	wg  sync.WaitGroup

	Username string
	Perms    map[string]int

	Account   string
	Accountid int
	Key       string
	Password  string

	Hostid       int
	Host         string
	Hostname     string
	Port         int
	ProxyCommand string
	ProxyAccount int
	Hostkeys     string

	RecordId int64
}

func (srv *Server) createSshConnServer(username, account, host string) (scs SshConnServer, err error) {
	ci := &ConnInfo{
		srv:      srv,
		db:       srv.db,
		Username: username,
		Perms:    make(map[string]int, 0),
		Account:  account,
		Host:     host,
	}

	err = ci.loadHost()
	if err != nil {
		return
	}

	err = ci.loadAccount()
	if err != nil {
		return
	}

	err = ci.loadPerms()
	if err != nil {
		return
	}

	err = ci.insertRecord()
	if err != nil {
		return
	}

	return ci, nil
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

func (ci *ConnInfo) ChkPerm(name string) (ok bool) {
	_, ok = ci.Perms[name]
	return
}

func (ci *ConnInfo) clientBuilder() (client ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, err error) {
	// and try connect it as last step
	hostname := fmt.Sprintf("%s:%d", ci.Hostname, ci.Port)
	var conn net.Conn
	switch {
	case ci.ProxyAccount != 0:
		log.Info("ssh proxy: %s:%d with accountid %d",
			ci.Hostname, ci.Port, ci.ProxyAccount)
		conn, err = ci.connectProxy(ci.ProxyAccount, ci.Hostname, ci.Port)
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

	config, err := genClientConfig(ci.Hostkeys, ci.Account, ci.Key, ci.Password)
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

func (ci *ConnInfo) connectProxy(accountid int, desthost string, destport int) (conn net.Conn, err error) {
	account, keys, password, hostname, port, hostkeys, err := ci.getProxy(accountid)
	if err != nil {
		return
	}
	log.Info("ssh to %s@%s:%d", account, hostname, port)

	config, err := genClientConfig(hostkeys, account, keys, password)
	if err != nil {
		return
	}

	client, err := ssh.Dial("tcp",
		fmt.Sprintf("%s:%d", hostname, port), config)
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
