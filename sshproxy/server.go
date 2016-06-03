package sshproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type WebConfig struct {
	Listen  string
	Hostkey string
	Logdir  string
}

type Server struct {
	WebConfig
	webhost string
	srvcfg  *ssh.ServerConfig
	mu      sync.Mutex
	scss    map[net.Addr]SshConnServer
	cnt     *Counter
}

func CreateServer(webhost string) (srv *Server, err error) {
	srv = &Server{
		scss:    make(map[net.Addr]SshConnServer, 0),
		webhost: webhost,
		cnt:     CreateCounter(CONN_PROTECT),
	}
	srv.srvcfg = &ssh.ServerConfig{
		PublicKeyCallback: srv.authUser,
	}

	v := &url.Values{}
	err = srv.GetJson("/l/cfg", false, v, &srv.WebConfig)
	if err != nil {
		panic(err.Error())
	}
	log.Debug("config: %#v", srv.WebConfig)

	private, err := ssh.ParsePrivateKey([]byte(srv.WebConfig.Hostkey))
	if err != nil {
		log.Error("failed to parse keyfile: %s", err.Error())
		return
	}
	srv.srvcfg.AddHostKey(private)

	return
}

func (srv *Server) GetJson(base string, post bool, v *url.Values, obj interface{}) (err error) {
	var resp *http.Response
	if post {
		u := fmt.Sprintf("http://%s%s", srv.webhost, base)
		log.Info("post url: %s", u)
		buf := bytes.NewBufferString(v.Encode())
		resp, err = http.Post(u, "pplication/x-www-form-urlencoded", buf)
	} else {
		u := fmt.Sprintf("http://%s%s?%s", srv.webhost, base, v.Encode())
		log.Info("get url: %s", u)
		resp, err = http.Get(u)
	}
	if err != nil {
		log.Error("query failed: %s", err.Error())
		return
	}
	defer resp.Body.Close()

	if obj == nil {
		return
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&obj)
	if err != nil {
		log.Error("decode json failed: %s", err.Error())
		return
	}
	return
}

func (srv *Server) getConnInfo(remote net.Addr) (scs SshConnServer, err error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// get RemoteAddr from ServerConn, and get user and host from AuthUser
	scs, ok := srv.scss[remote]
	if !ok {
		fmt.Printf("%v", srv.scss, remote)
		return nil, ErrSCSNotFound
	}
	return
}

func (srv *Server) closeConn(remote net.Addr) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.scss, remote)
}

func (srv *Server) serveConn(nConn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, srv.srvcfg)
	if err != nil {
		log.Error("failed to handshake: %s", err.Error())
		srv.Failed(nConn.RemoteAddr())
		return
	}
	defer conn.Close()

	remote := nConn.RemoteAddr()
	scs, err := srv.getConnInfo(remote)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	defer srv.closeConn(remote)

	err = scs.Serve(conn, chans, reqs)
	if err != nil {
		log.Error("%s", err.Error())
	}
	return
}

func (srv *Server) createSshConnServer(username, remote, account, host string) (scs SshConnServer, err error) {
	switch {
	case host == "_":
		log.Notice("user %s@%s wanna audit log %s", username, remote, account)

		var id int
		id, err = strconv.Atoi(account)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}

		ri := &ReviewInfo{
			srv:          srv,
			Username:     username,
			RecordLogsId: id,
		}

		err = ri.init()
		if err != nil {
			return
		}

		return ri, nil
	default:
		log.Notice("user %s@%s will connect %s@%s.", username, remote, account, host)

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
	return
}

func (srv *Server) findPubkey(key ssh.PublicKey) (username string, err error) {
	pubkey := base64.StdEncoding.EncodeToString(key.Marshal())
	v := &url.Values{}
	v.Add("pubkey", pubkey)

	type PubkeyRslt struct {
		Name     string
		Username string
	}
	rslt := &PubkeyRslt{}

	err = srv.GetJson("/l/pubk", false, v, rslt)
	if err != nil {
		return
	}
	username = rslt.Username
	return
}

func (srv *Server) authUser(meta ssh.ConnMetadata, key ssh.PublicKey) (perm *ssh.Permissions, err error) {
	userid := meta.User()
	log.Debug("username from client: %s", userid)
	remote := meta.RemoteAddr()

	// split user and host from username
	i := strings.SplitN(userid, "@", 2)
	if len(i) < 2 {
		i = strings.SplitN(userid, "/", 2)
		if len(i) < 2 {
			err = ErrIllegalUserName
			log.Error("%s", err.Error())
			return
		}
	}
	account := i[0]
	host := i[1]

	username, err := srv.findPubkey(key)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	scs, err := srv.createSshConnServer(username, remote.String(), account, host)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	if scs == nil {
		log.Error("can't create server")
		return
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.scss[remote] = scs
	return
}

func (srv *Server) Protect(addr net.Addr) (err error) {
	taddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return
	}
	s := string(taddr.IP)
	if srv.cnt.Number(s) > MAX_FAILED {
		return ErrFailedTooMany
	}
	return
}

func (srv *Server) Failed(addr net.Addr) {
	taddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return
	}
	s := string(taddr.IP)
	srv.cnt.Add(s, 1)
}

func (srv *Server) MainLoop() {
	listener, err := net.Listen("tcp", srv.WebConfig.Listen)
	if err != nil {
		log.Error("failed to listen for connection: %s", err.Error())
		return
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Error("failed to accept incoming connection: %s", err.Error())
			continue
		}
		err = srv.Protect(nConn.RemoteAddr())
		if err != nil {
			log.Warning("refused to connect with %s for too much failed.",
				nConn.RemoteAddr().String())
			continue
		}
		log.Debug("net connect coming.")

		go srv.serveConn(nConn)
	}
}
