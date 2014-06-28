package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	// "github.com/shell909090/sshproxy/term"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
)

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

func ReadPayload(payload []byte) (strs []string) {
	for len(payload) >= 4 {
		size := binary.BigEndian.Uint32(payload[:4])
		s := string(payload[4 : 4+size])
		strs = append(strs, s)
		payload = payload[4+size:]
	}
	return
}

type ABWriteCloser struct {
	a io.WriteCloser
	b []io.WriteCloser
}

func CreateABWriteCloser(a io.WriteCloser, bs ...io.WriteCloser) (abc *ABWriteCloser) {
	abc = &ABWriteCloser{a: a, b: make([]io.WriteCloser, 0)}
	for _, b := range bs {
		abc.b = append(abc.b, b.(io.WriteCloser))
	}
	return
}

func (abc *ABWriteCloser) Write(p []byte) (n int, err error) {
	log.Debug("write out: %d.", len(p))
	for _, b := range abc.b {
		defer b.Write(p)
	}
	return abc.a.Write(p)
}

func (abc *ABWriteCloser) Close() (err error) {
	for _, b := range abc.b {
		defer b.Close()
	}
	return abc.a.Close()
}

type ConnInfo struct {
	srv      *Server
	Realname string
	Username string
	Host     string
	Hostname string
	Port     int
	Hostkeys string
	RecordId int64

	Type      string
	ch_ready  chan int
	RemoteDir string

	chin  ssh.Channel
	chout ssh.Channel

	out io.WriteCloser
	in  io.WriteCloser
	cmd io.WriteCloser
	// e   *term.Emu
}

func (srv *Server) createConnInfo(realname, username, host string) (ci *ConnInfo, err error) {
	// chcmd := make(chan string, 0)

	ci = &ConnInfo{
		srv:      srv,
		Realname: realname,
		Username: username,
		Host:     host,

		ch_ready: make(chan int, 0),

		// e:        term.CreateEmu(chcmd, 80, 25),
	}

	err = srv.db.QueryRow("SELECT hostname, port, hostkeys FROM hosts WHERE host=?", host).Scan(
		&ci.Hostname, &ci.Port, &ci.Hostkeys)
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

	ci.out, err = os.OpenFile(fmt.Sprintf("%s/%d.out", srv.LogDir, ci.RecordId),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	ci.in, err = os.OpenFile(fmt.Sprintf("%s/%d.in", srv.LogDir, ci.RecordId),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

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

func (ci *ConnInfo) on_file_transmit(filename string, size int) {
	log.Info("transmit %s with name: %s, size: %d, remote dir: %s",
		ci.Type, filename, size, ci.RemoteDir)

	_, err := ci.srv.db.Exec("INSERT INTO record_files(recordid, type, filename, size, remotedir) VALUES (?, ?, ?, ?, ?)", ci.RecordId, ci.Type, filename, size, ci.RemoteDir)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	return
}

func (ci *ConnInfo) on_req(req *ssh.Request) (err error) {
	switch req.Type {
	case "env":
		envs := ReadPayload(req.Payload)
		for _, env := range envs {
			log.Debug("env: %s", env)
		}
	case "exec":
		cmds := ReadPayload(req.Payload)
		log.Debug("exec with cmd: %s.", cmds[0])
		cmds = strings.Split(cmds[0], " ")
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
	}
	return nil
}

func (ci *ConnInfo) serveReqs(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Debug("new req: %s(reply: %t, payload: %d).",
			req.Type, req.WantReply, len(req.Payload))

		err := ci.on_req(req)
		if err != nil {
			log.Error("%s", err.Error())
			if req.WantReply {
				err = req.Reply(false, nil)
				if err != nil {
					log.Error("%s", err.Error())
					return
				}
			}
			continue
		}

		b, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}
		log.Debug("send req ok: %s(result: %t)", req.Type, b)

		err = req.Reply(b, nil)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}
		log.Debug("reply req ok: %s(result: %t)", req.Type, b)
	}
}

// session
// direct-tcpip
func (ci *ConnInfo) serveChan(client *ssh.Client, newChannel ssh.NewChannel) {
	log.Debug("new channel: %s (len: %d)",
		newChannel.ChannelType(), len(newChannel.ExtraData()))

	if newChannel.ChannelType() != "session" {
		return
	}

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

	ci.chin, ci.chout = chin, chout

	go ci.serveReqs(chin, outreqs)
	go ci.serveReqs(chout, inreqs)

	<-ci.ch_ready

	switch ci.Type {
	case "shell":
		go CopyChan(CreateABWriteCloser(chout, ci.in), chin)
		go CopyChan(CreateABWriteCloser(chin, ci.out), chout)
	case "scpto":
		go CopyChan(CreateABWriteCloser(chout, CreateScpStream(ci)), chin)
		go CopyChan(chin, chout)
	case "scpfrom":
		go CopyChan(chout, chin)
		go CopyChan(CreateABWriteCloser(chin, CreateScpStream(ci)), chout)
	}

}
