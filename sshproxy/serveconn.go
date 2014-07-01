package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"fmt"
)

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

func (ci *ConnInfo) serveChan(conn ssh.Conn, newChan ssh.NewChannel) (err error) {
	switch newChan.ChannelType() {
	case "session":
	case "direct-tcpip":
		ci.Type = "tcpip"
		ip, port, _, _, err := getTcpInfo(newChan.ExtraData())
		if err != nil {
			return err
		}
		log.Debug("mapping local port to %s:%d", ip, port)
		ci.ch_ready <- 1
	case "forwarded-tcpip":
		ci.Type = "tcpip"
		ip, port, _, _, err := getTcpInfo(newChan.ExtraData())
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
		go MultiCopyClose(chin, chout, &DebugStream{"out"})
		go MultiCopyClose(chout, chin, &DebugStream{"in"})
	case "sshagent":
		go MultiCopyClose(chin, chout, &DebugStream{"out"})
		go MultiCopyClose(chout, chin, &DebugStream{"in"})
	case "shell":
		go MultiCopyClose(chin, chout, ci.in)
		go MultiCopyClose(chout, chin, ci.out)
	case "scpto":
		go MultiCopyClose(chin, chout, CreateScpStream(ci))
		go MultiCopyClose(chout, chin)
	case "scpfrom":
		go MultiCopyClose(chin, chout)
		go MultiCopyClose(chout, chin, CreateScpStream(ci))
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
