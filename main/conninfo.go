package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"github.com/shell909090/sshproxy/term"
	"io"
	"net"
	"os"
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
	Realname string
	Username string
	Host     string
	Hostname string
	Port     int
	Hostkeys string
	RecordId int64

	chin  ssh.Channel
	chout ssh.Channel

	raw io.WriteCloser
	cmd io.WriteCloser
	e   *term.Emu
}

func (srv *Server) createConnInfo(db *sql.DB, realname, username, host string) (ci *ConnInfo, err error) {
	chcmd := make(chan string, 0)

	ci = &ConnInfo{
		Realname: realname,
		Username: username,
		Host:     host,
		e:        term.CreateEmu(chcmd, 80, 25),
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

	filepath := fmt.Sprintf("%s/%d.raw", srv.Config.LogDir, ci.RecordId)
	ci.raw, err = os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	filepath = fmt.Sprintf("%s/%d.cmd", srv.Config.LogDir, ci.RecordId)
	ci.cmd, err = os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	return
}

func (ci *ConnInfo) Final(srv *Server) {
	_, err := srv.db.Exec("UPDATE records SET endtime=CURRENT_TIMESTAMP WHERE id=?", ci.RecordId)
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

func (ci *ConnInfo) serveReqs(ch ssh.Channel, reqs <-chan *ssh.Request) {
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

func (ci *ConnInfo) serveChan(client *ssh.Client, newChannel ssh.NewChannel) {
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

	go CopyChan(chout, chin)
	go CopyChan(CreateABWriteCloser(chin, ci.raw, ci.e), chout)
}
