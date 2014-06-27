package main

import (
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"
)

type Server struct {
	Config
	cis                  map[net.Addr]*ConnInfo
	mu                   sync.Mutex
	db                   *sql.DB
	stmtInsertRecord     *sql.Stmt
	stmtSelectUserPubKey *sql.Stmt
}

func CreateServer(cfg Config) (srv *Server, err error) {
	srv = &Server{
		Config: cfg,
		cis:    make(map[net.Addr]*ConnInfo, 0),
	}

	srv.db, err = sql.Open("sqlite3", srv.DBFile)
	if err != nil {
		panic(err.Error())
	}

	srv.stmtInsertRecord, err = srv.db.Prepare("INSERT INTO records(realname, username, host) values(?,?,?)")
	if err != nil {
		panic(err.Error())
		return
	}

	srv.stmtSelectUserPubKey, err = srv.db.Prepare("SELECT realname FROM user_pubkey WHERE pubkey=?")
	if err != nil {
		panic(err.Error())
		return
	}

	return
}

func (srv *Server) serveReqs(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Debug("new req: %s(reply: %t).", req.Type, req.WantReply)

		b, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}
		log.Debug("send req ok: %s %t", req.Type, b)

		err = req.Reply(b, nil)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}
		log.Debug("reply req ok: %s", req.Type)
	}
}

func (srv *Server) serveChan(client *ssh.Client, newChannel ssh.NewChannel, ci *ConnInfo) {
	chout, outreqs, err := client.OpenChannel(
		newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		newChannel.Reject(ssh.UnknownChannelType, err.Error())
		log.Error("reject channel: %s", err.Error())
		return
	}
	log.Debug("open channel ok.")

	chin, inreqs, err := newChannel.Accept()
	if err != nil {
		log.Error("could not accept channel.")
		return
	}
	log.Debug("accept channel ok.")

	wl, err := srv.CreateLogger(chin, ci)
	if err != nil {
		log.Error("can't create logger.")
		return
	}

	go srv.serveReqs(chin, outreqs)
	go srv.serveReqs(chout, inreqs)

	go CopyChan(chout, chin)
	go CopyChan(wl, chout)
}

func (srv *Server) getConnInfo(remote net.Addr) (ci *ConnInfo, err error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// get RemoteAddr from ServerConn, and get user and host from AuthUser
	ci, ok := srv.cis[remote]
	if !ok {
		fmt.Printf("%v", srv.cis, remote)
		return nil, ErrCINotFound
	}
	return
}

func (srv *Server) clientBuilder(ci *ConnInfo) (client *ssh.Client, err error) {
	// load private key from user and host
	var privateStr string
	err = srv.db.QueryRow("SELECT keys FROM accounts WHERE username=? AND host=?",
		ci.username, ci.host).Scan(&privateStr)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	private, err := ssh.ParsePrivateKey([]byte(privateStr))
	if err != nil {
		log.Error("failed to parse keyfile: %s", err.Error())
		return
	}

	config := &ssh.ClientConfig{
		User: ci.username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(private),
		},
		HostKeyCallback: ci.checkHostKey,
	}

	// and try connect it as last step
	hostname := fmt.Sprintf("%s:%d", ci.hostname, ci.port)
	client, err = ssh.Dial("tcp", hostname, config)
	if err != nil {
		log.Error("Failed to dial: %s", err.Error())
		return
	}
	return
}

func (srv *Server) serveConn(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	remote := conn.RemoteAddr()
	ci, err := srv.getConnInfo(remote)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	client, err := srv.clientBuilder(ci)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	defer client.Close()

	log.Debug("handshake ok")
	for newChannel := range chans {
		log.Debug("new channel: %s", newChannel.ChannelType())
		srv.serveChan(client, newChannel, ci)
	}

	srv.closeConn(remote, ci)
}

func (srv *Server) closeConn(remote net.Addr, ci *ConnInfo) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	delete(srv.cis, remote)
	log.Info("Connect closed.")
}

func (srv *Server) findPubkey(key ssh.PublicKey) (realname string, err error) {
	err = srv.stmtSelectUserPubKey.QueryRow(string(key.Marshal())).Scan(&realname)
	switch err {
	case sql.ErrNoRows:
		return "", ErrIllegalPubkey
	case nil:
	default:
		log.Error("%s", err.Error())
	}
	return
}

func CheckAccess(realname, username, host string, remote net.Addr) (err error) {
	log.Info("user %s@%s will connect %s@%s.", realname, remote, username, host)
	return
}

func (srv *Server) createConnInfo(realname, username, host string) (ci *ConnInfo, err error) {
	ci = &ConnInfo{
		realname: realname,
		username: username,
		host:     host,
	}
	err = srv.db.QueryRow("SELECT hostname, port, hostkeys FROM hosts WHERE host=?", host).Scan(
		&ci.hostname, &ci.port, &ci.hostkeys)
	if err != nil {
		log.Error("%s", err.Error())
		err = ErrHostKey
		return
	}

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
	username := i[0]
	host := i[1]

	realname, err := srv.findPubkey(key)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	// check if realname can access user and host
	err = CheckAccess(realname, username, host, remote)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	ci, err := srv.createConnInfo(realname, username, host)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	// set user and host in meta.RemoteAddr
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.cis[remote] = ci
	return
}

func (srv *Server) MainLoop() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: srv.authUser,
	}

	private, err := LoadPrivateKey(srv.HostPrivateKeyFile)
	if err != nil {
		return
	}
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", srv.Listen)
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
		log.Debug("net connect coming.")

		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Error("failed to handshake: %s", err.Error())
			continue
		}
		go srv.serveConn(conn, chans, reqs)
	}
}
