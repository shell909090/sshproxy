package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"
)

func LoadPrivateKey(filename string) (private ssh.Signer, err error) {
	log.Info("load private key: %s", filename)

	privateBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error("failed to load keyfile: %s", err.Error())
		return
	}
	private, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Error("failed to parse keyfile: %s", err.Error())
		return
	}
	return
}

// func LoadAuthorizedKey(filename string) (publices []ssh.PublicKey, err error) {
// 	log.Info("load authorized key: %s", filename)

// 	publicBytes, err := ioutil.ReadFile(filename)
// 	if err != nil {
// 		log.Error("failed to load pubkeyfile: %s", err.Error())
// 		return
// 	}
// 	rest := publicBytes
// 	for {
// 		var public ssh.PublicKey
// 		public, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
// 		if err != nil {
// 			err = nil
// 			break
// 		}
// 		publices = append(publices, public)
// 	}
// 	return
// }

type Server struct {
	Config
	conninfos map[net.Addr]*ConnInfo
	mu        sync.Mutex

	db                   *sql.DB
	stmtInsertRecord     *sql.Stmt
	stmtSelectUserPubKey *sql.Stmt
}

func CreateServer(cfg Config) (srv *Server, err error) {
	srv = &Server{
		Config:    cfg,
		conninfos: make(map[net.Addr]*ConnInfo, 0),
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

func (srv *Server) ServeReqs(ch ssh.Channel, reqs <-chan *ssh.Request) {
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

func CopyChan(d io.WriteCloser, s io.ReadCloser) {
	defer s.Close()
	defer d.Close()
	_, err := io.Copy(d, s)

	switch err {
	case io.EOF:
	case nil:
	default:
		log.Error("%s", err.Error())
	}
	return
}

func (srv *Server) ServeChan(client *ssh.Client, newChannel ssh.NewChannel, ci *ConnInfo) {
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

	go srv.ServeReqs(chin, outreqs)
	go srv.ServeReqs(chout, inreqs)

	go CopyChan(chout, chin)
	go CopyChan(wl, chout)
}

type ConnInfo struct {
	username string
	host     string
	realname string
}

func (srv *Server) getConnInfo(remote net.Addr) (ci *ConnInfo, err error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// get RemoteAddr from ServerConn, and get user and host from AuthUser
	ci, ok := srv.conninfos[remote]
	if !ok {
		return nil, ErrCINotFound
	}
	delete(srv.conninfos, remote)
	return
}

func (srv *Server) checkHostKey(hostname string, remote net.Addr, key ssh.PublicKey) (err error) {
	log.Debug("check hostkey: %s", hostname)

	var hostkeyStr string
	err = srv.db.QueryRow("SELECT public FROM hosts WHERE host=?", hostname).Scan(&hostkeyStr)
	if err != nil {
		log.Error("%s", err.Error())
		err = ErrHostKey
		return
	}

	hostkey := key.Marshal()
	log.Info("remote hostkey: %s", key.Type())

	rest := []byte(hostkeyStr)
	for {
		var public ssh.PublicKey
		public, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			err = nil
			break
		}
		if key.Type() == public.Type() && bytes.Compare(hostkey, public.Marshal()) == 0 {
			log.Info("host key match: %s", hostname)
			return nil
		}
	}

	log.Info("host key not match: %s", hostname)
	return ErrHostKey
}

func (srv *Server) clientBuilder(conn *ssh.ServerConn) (client *ssh.Client, ci *ConnInfo, err error) {
	remote := conn.RemoteAddr()
	ci, err = srv.getConnInfo(remote)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	// load private key from user and host
	var port int
	var privateStr string
	err = srv.db.QueryRow("SELECT keys, port FROM accounts WHERE username=? AND host=?",
		ci.username, ci.host).Scan(&privateStr, port)
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
		HostKeyCallback: srv.checkHostKey,
	}

	// and try connect it as last step
	host := fmt.Sprintf("%s:%d", ci.host, port)
	client, err = ssh.Dial("tcp", host, config)
	if err != nil {
		log.Error("Failed to dial: %s", err.Error())
		return
	}
	return
}

func (srv *Server) serveConn(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	client, ci, err := srv.clientBuilder(conn)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	defer client.Close()

	log.Debug("handshake ok")
	for newChannel := range chans {
		log.Debug("new channel: %s", newChannel.ChannelType())
		srv.ServeChan(client, newChannel, ci)
	}

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
		return
	}

	// set user and host in meta.RemoteAddr
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.conninfos[remote] = &ConnInfo{
		username: username,
		host:     host,
		realname: realname,
	}
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
