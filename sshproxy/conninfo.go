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
	"time"
)

type ConnInfo struct {
	srv *Server
	wg  sync.WaitGroup

	Realname     string
	Username     string
	Host         string
	Hostname     string
	Port         int
	ProxyCommand string
	Hostkeys     string
	RecordId     int64
	Starttime    time.Time

	Type      string
	ch_ready  chan int
	RemoteDir string

	chin  ssh.Channel
	chout ssh.Channel

	out io.WriteCloser
	in  io.WriteCloser
	cmd io.WriteCloser
}

func (srv *Server) createConnInfo(realname, username, host string) (ci *ConnInfo, err error) {
	ci = &ConnInfo{
		srv:      srv,
		Realname: realname,
		Username: username,
		Host:     host,

		ch_ready: make(chan int, 0),
	}

	err = srv.db.QueryRow("SELECT hostname, port, proxycommand, hostkeys FROM hosts WHERE host=?",
		host).Scan(&ci.Hostname, &ci.Port, &ci.ProxyCommand, &ci.Hostkeys)
	if err != nil {
		log.Error("%s", err.Error())
		err = ErrHostKey
		return
	}

	res, err := srv.db.Exec("INSERT INTO records(realname, username, host) values(?,?,?)",
		ci.Realname, ci.Username, ci.Host)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	ci.RecordId, err = res.LastInsertId()
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	err = ci.prepareFile()
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	return
}

func (ci *ConnInfo) prepareFile() (err error) {
	var Starttime string

	err = ci.srv.db.QueryRow("SELECT starttime FROM records WHERE id=?",
		ci.RecordId).Scan(&Starttime)
	if err != nil {
		return
	}
	ci.Starttime, err = time.Parse("2006-01-02 03:04:05", Starttime)
	if err != nil {
		return
	}

	logDir := fmt.Sprintf("%s/%s", ci.srv.LogDir, ci.Starttime.Format("200601"))
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		return
	}

	ci.out, err = os.OpenFile(fmt.Sprintf("%s/%d.out", logDir, ci.RecordId),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return
	}

	ci.in, err = os.OpenFile(fmt.Sprintf("%s/%d.in", logDir, ci.RecordId),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	return
}

func (ci *ConnInfo) Close() (err error) {
	_, err = ci.srv.db.Exec("UPDATE records SET endtime=CURRENT_TIMESTAMP WHERE id=?",
		ci.RecordId)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	return
}

func (ci *ConnInfo) checkHostKey(hostname string, remote net.Addr, key ssh.PublicKey) (err error) {
	log.Debug("check hostkey: %s", hostname)

	hostkey := key.Marshal()
	log.Info("remote hostkey: %s", key.Type())

	rest := []byte(ci.Hostkeys)
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

func (ci *ConnInfo) clientBuilder() (client ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, err error) {
	// load private key from user and host
	var privateStr string
	err = ci.srv.db.QueryRow("SELECT keys FROM accounts WHERE username=? AND host=?",
		ci.Username, ci.Host).Scan(&privateStr)
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
		User: ci.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(private),
		},
		HostKeyCallback: ci.checkHostKey,
	}

	// and try connect it as last step
	hostname := fmt.Sprintf("%s:%d", ci.Hostname, ci.Port)
	var conn net.Conn
	if ci.ProxyCommand == "" {
		conn, err = net.Dial("tcp", hostname)
		if err != nil {
			log.Error("ssh dial failed: %s", err.Error())
			return
		}
	} else {
		// FIXME: dangerous
		log.Info("proxy command: %s", ci.ProxyCommand)
		conn, err = RunCmdNet(ci.ProxyCommand)
		if err != nil {
			log.Error("proxy command failed: %s", err.Error())
			return
		}
	}
	client, chans, reqs, err = ssh.NewClientConn(conn, hostname, config)
	if err != nil {
		log.Error("ssh client conn failed: %s", err.Error())
		return
	}
	return
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

func (ci *ConnInfo) on_file_transmit(filename string, size int) {
	log.Notice("%s with name: %s, size: %d, remote dir: %s",
		ci.Type, filename, size, ci.RemoteDir)

	_, err := ci.srv.db.Exec("INSERT INTO record_files(recordid, type, filename, size, remotedir) VALUES (?, ?, ?, ?, ?)", ci.RecordId, ci.Type, filename, size, ci.RemoteDir)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
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

func (ci *ConnInfo) serveChanReq(ch ssh.Channel, req *ssh.Request) (err error) {
	err = ci.onChanReq(req)
	if err != nil {
		log.Error("%s", err.Error())
		errrpy := req.Reply(false, nil)
		if errrpy != nil {
			return
		}
		return
	}

	r, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		return
	}
	log.Debug("send chan req ok: %s(result: %t)", req.Type, r)

	err = req.Reply(r, nil)
	if err != nil {
		return
	}
	log.Debug("reply chan req ok: %s(result: %t)", req.Type, r)
	return
}

func (ci *ConnInfo) serveChanReqs(ch ssh.Channel, reqs <-chan *ssh.Request) {
	log.Debug("chan reqs begin.")
	for req := range reqs {
		log.Debug("new chan req: %s(reply: %t, payload: %d).",
			req.Type, req.WantReply, len(req.Payload))
		err := ci.serveChanReq(ch, req)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}
	}
	log.Debug("chan reqs end.")
}

func (ci *ConnInfo) getTcpInfo(d []byte) (srcip string, srcport uint32, dstip string, dstport uint32, err error) {
	srcip, d, err = ReadPayloadString(d)
	if err != nil {
		return
	}
	srcport, d, err = ReadPayloadUint32(d)
	if err != nil {
		return
	}
	dstip, d, err = ReadPayloadString(d)
	if err != nil {
		return
	}
	dstport, d, err = ReadPayloadUint32(d)
	if err != nil {
		return
	}
	return
}

func (ci *ConnInfo) serveChan(conn ssh.Conn, newChan ssh.NewChannel) (err error) {
	switch newChan.ChannelType() {
	case "session":
	case "direct-tcpip":
		ci.Type = "tcpip"
		ip, port, _, _, err := ci.getTcpInfo(newChan.ExtraData())
		if err != nil {
			return err
		}
		log.Debug("mapping local port to %s:%d", ip, port)
		ci.ch_ready <- 1
	case "forwarded-tcpip":
		ci.Type = "tcpip"
		ip, port, _, _, err := ci.getTcpInfo(newChan.ExtraData())
		if err != nil {
			return err
		}
		log.Debug("mapping from remote port to %s:%d", ip, port)
		ci.ch_ready <- 1
	case "auth-agent@openssh.com":
		ci.Type = "sshagent"
	default:
		log.Error("channel type %s not supported.", newChan.ChannelType())
		err = ErrChanTypeNotSupported
		return
	}

	chout, outreqs, err := conn.OpenChannel(
		newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
		// TODO: strace UnknownChannelType
		newChan.Reject(ssh.UnknownChannelType, err.Error())
		log.Error("reject channel: %s", err.Error())
		return
	}
	log.Debug("open channel ok.")

	chin, inreqs, err := newChan.Accept()
	if err != nil {
		log.Error("could not accept channel.")
		return
	}
	log.Debug("accept channel ok.")

	ci.chin, ci.chout = chin, chout

	go ci.serveChanReqs(chin, outreqs)
	go ci.serveChanReqs(chout, inreqs)

	<-ci.ch_ready

	switch ci.Type {
	case "tcpip":
		go CopyChan(chout, chin)
		go CopyChan(chin, chout)
	case "sshagent":
		go CopyChan(CreateMultiWriteCloser(chout, &DebugStream{"out"}), chin)
		go CopyChan(CreateMultiWriteCloser(chin, &DebugStream{"in"}), chout)
	case "shell":
		go CopyChan(CreateMultiWriteCloser(chout, ci.in), chin)
		go CopyChan(CreateMultiWriteCloser(chin, ci.out), chout)
	case "scpto":
		go CopyChan(CreateMultiWriteCloser(chout, CreateScpStream(ci)), chin)
		go CopyChan(chin, chout)
	case "scpfrom":
		go CopyChan(chout, chin)
		go CopyChan(CreateMultiWriteCloser(chin, CreateScpStream(ci)), chout)
	}
	return
}

func (ci *ConnInfo) serveChans(conn ssh.Conn, chans <-chan ssh.NewChannel) (err error) {
	defer ci.wg.Done()
	log.Debug("chans begin.")
	for newChan := range chans {
		log.Debug("new channel: %s (len: %d)",
			newChan.ChannelType(), len(newChan.ExtraData()))
		err = ci.serveChan(conn, newChan)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}
	}
	log.Debug("chans ends.")
	return
}
