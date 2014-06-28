package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
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
	b io.WriteCloser
}

func CreateChanWriteCloser(a io.WriteCloser, b io.WriteCloser) (abc *ABWriteCloser) {
	return &ABWriteCloser{a: a, b: b}
}

func (abc *ABWriteCloser) Write(p []byte) (n int, err error) {
	defer abc.a.Write(p)
	return abc.b.Write(p)
}

func (cwc *ChanWriteCloser) Close() (err error) {
	defer abc.a.Close()
	return abc.b.Close()
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
}

func (srv *Server) createConnInfo(db *sql.DB, realname, username, host string) (ci *ConnInfo, err error) {
	ci = &ConnInfo{
		Realname: realname,
		Username: username,
		Host:     host,
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
	go CopyChan(ABWriteCloser(ci.raw, chin), chout)
}
