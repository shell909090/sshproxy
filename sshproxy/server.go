package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
)

type Server struct {
	LogDir string
	cis    map[net.Addr]*ConnInfo
	mu     sync.Mutex
	db     *sql.DB
}

func CreateServer(dbdriver, dbfile, logdir string) (srv *Server, err error) {
	srv = &Server{
		LogDir: logdir,
		cis:    make(map[net.Addr]*ConnInfo, 0),
	}

	srv.db, err = sql.Open(dbdriver, dbfile)
	if err != nil {
		panic(err.Error())
	}

	return
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

func (srv *Server) serveConn(srvConn ssh.ServerConn, srvChans <-chan ssh.NewChannel, srvReqs <-chan *ssh.Request) {
	defer srvConn.Close()

	remote := srvConn.RemoteAddr()
	ci, err := srv.getConnInfo(remote)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	defer srv.closeConn(remote, ci)
	defer ci.Close()

	cliConn, cliChans, cliReqs, err := ci.clientBuilder()
	if err != nil {
		log.Error("%s", err.Error())
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
}

func (srv *Server) closeConn(remote net.Addr, ci *ConnInfo) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.cis, remote)
}

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

func (srv *Server) CheckAccess(username, account, host string, remote net.Addr) (err error) {
	log.Notice("user %s@%s will connect %s@%s.", username, remote, account, host)
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

	// check if realname can access user and host
	err = srv.CheckAccess(username, account, host, remote)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	ci, err := srv.createConnInfo(username, account, host)
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

// FIXME: time limit
func (srv *Server) MainLoop(HostPrivateKeyFile, Listen string) {
	config := &ssh.ServerConfig{
		PublicKeyCallback: srv.authUser,
	}

	private, err := LoadPrivateKey(HostPrivateKeyFile)
	if err != nil {
		return
	}
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", Listen)
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
		go srv.serveConn(*conn, chans, reqs)
	}
}
