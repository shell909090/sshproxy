package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"
)

type SshConnServer interface {
	Serve(ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request) error
}

type Server struct {
	db     *sql.DB
	mu     sync.Mutex
	scss   map[net.Addr]SshConnServer
	LogDir string
}

func CreateServer(dbdriver, dbfile, logdir string) (srv *Server, err error) {
	srv = &Server{
		scss:   make(map[net.Addr]SshConnServer, 0),
		LogDir: logdir,
	}

	srv.db, err = sql.Open(dbdriver, dbfile)
	if err != nil {
		panic(err.Error())
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

func (srv *Server) serveConn(srvConn ssh.ServerConn, srvChans <-chan ssh.NewChannel, srvReqs <-chan *ssh.Request) {
	defer srvConn.Close()

	remote := srvConn.RemoteAddr()
	scs, err := srv.getConnInfo(remote)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	defer srv.closeConn(remote)

	err = scs.Serve(srvConn, srvChans, srvReqs)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
}

func (srv *Server) closeConn(remote net.Addr) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.scss, remote)
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

	log.Notice("user %s@%s will connect %s@%s.", username, remote, account, host)
	scs, err := srv.createSshConnServer(username, account, host)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	// set user and host in meta.RemoteAddr
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.scss[remote] = scs
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
