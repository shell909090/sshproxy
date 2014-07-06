package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"strings"
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
	err = ci.onChanType(newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
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

	go ci.serveChanReqs(chin, outreqs)
	go ci.serveChanReqs(chout, inreqs)

	<-ci.ch_ready

	switch ci.Type {
	case "local", "remote":
		go MultiCopyClose(chin, chout, &DebugStream{"out"})
		go MultiCopyClose(chout, chin, &DebugStream{"in"})
	case "sshagent":
		go MultiCopyClose(chin, chout, &DebugStream{"out"})
		go MultiCopyClose(chout, chin, &DebugStream{"in"})
	case "shell":
		out, err := ci.prepareFile("out", "")
		if err != nil {
			return err
		}
		go MultiCopyClose(chin, chout)
		go MultiCopyClose(chout, chin, out)
	case "exec":
		out, err := ci.prepareFile("out", strings.Join(ci.ExecCmds, "\r"))
		if err != nil {
			return err
		}
		go MultiCopyClose(chin, chout)
		go MultiCopyClose(chout, chin, out)
	case "scpto":
		if ci.srv.logfiletransfer >= 1 {
			go MultiCopyClose(chin, chout, CreateScpStream(ci))
		} else {
			go MultiCopyClose(chin, chout)
		}
		go MultiCopyClose(chout, chin)
	case "scpfrom":
		go MultiCopyClose(chin, chout)
		if ci.srv.logfiletransfer >= 1 {
			go MultiCopyClose(chout, chin, CreateScpStream(ci))
		} else {
			go MultiCopyClose(chout, chin)
		}
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
