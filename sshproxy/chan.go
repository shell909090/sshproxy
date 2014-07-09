package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

type ChanInfo struct {
	ci           *ConnInfo
	RecordLogsId int
	ch           chan int
	Type         string
	RemoteDir    string
	ExecCmds     []string
}

func CreateChanInfo(ci *ConnInfo) (chi *ChanInfo) {
	chi = &ChanInfo{
		ci:   ci,
		ch:   make(chan int, 1),
		Type: "unknown",
	}
	return chi
}

func (chi *ChanInfo) insertRecordLogs(rltype, log1, log2 string, num1 int) (id int, err error) {
	v := &url.Values{}
	v.Add("recordid", fmt.Sprintf("%d", chi.ci.RecordId))
	v.Add("type", rltype)
	v.Add("log1", log1)
	v.Add("log2", log2)
	v.Add("num1", fmt.Sprintf("%d", num1))

	type RecordLogsRslt struct {
		Id int
	}
	rslt := &RecordLogsRslt{}

	err = chi.ci.srv.GetJson("/rlog/add", v, rslt)
	if err != nil {
		return
	}
	id = rslt.Id
	return
}

func (chi *ChanInfo) prepareFile(ext, cmd string) (w io.WriteCloser, err error) {
	logDir := fmt.Sprintf("%s/%s", chi.ci.srv.WebConfig.Logdir, chi.ci.Starttime.Format("20060102"))
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		return
	}

	chi.RecordLogsId, err = chi.insertRecordLogs(chi.Type, cmd, "", 0)
	if err != nil {
		return
	}

	w, err = os.OpenFile(fmt.Sprintf("%s/%d.%s", logDir, chi.RecordLogsId, ext),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	return
}

func (chi *ChanInfo) TcpForward(direct, ip string, port uint32) (err error) {
	log.Notice("mapping %s port to %s:%d", direct, ip, port)
	chi.RecordLogsId, err = chi.insertRecordLogs(chi.Type, ip, "", int(port))
	return
}

func (chi *ChanInfo) FileTransmit(filename string, size int) (err error) {
	log.Notice("%s with name: %s, size: %d, remote dir: %s",
		chi.Type, filename, size, chi.RemoteDir)
	chi.RecordLogsId, err = chi.insertRecordLogs(chi.Type, filename, chi.RemoteDir, size)
	return
}

func (chi *ChanInfo) FileData(b []byte) (err error) {
	return
}

func (chi *ChanInfo) onReq(req *ssh.Request) (err error) {
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

		switch cmds[0] {
		case "scp":
			switch cmds[len(cmds)-2] {
			case "-t":
				chi.Type = "scpto"
				if !chi.ci.ChkPerm("scpto") {
					close(chi.ch)
					return ErrNoPerms
				}
			case "-f":
				chi.Type = "scpfrom"
				if !chi.ci.ChkPerm("scpfrom") {
					close(chi.ch)
					return ErrNoPerms
				}
			}
			chi.ch <- 1
			chi.RemoteDir = cmds[len(cmds)-1]
			log.Info("session in %s mode, remote dir: %s.",
				chi.Type, chi.RemoteDir)
		default:
			chi.Type = "exec"
			chi.ch <- 1
			chi.ExecCmds = append(chi.ExecCmds, strs[0])
		}
	case "shell":
		if !chi.ci.ChkPerm("shell") {
			close(chi.ch)
			return ErrNoPerms
		}
		chi.Type = "shell"
		chi.ch <- 1
		log.Info("session in shell mode")
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

func (chi *ChanInfo) onType(chantype string, extra []byte) (err error) {
	switch chantype {
	case "session":
	case "direct-tcpip":
		if !chi.ci.ChkPerm("tcp") {
			close(chi.ch)
			return ErrNoPerms
		}

		chi.Type = "local"
		chi.ch <- 1

		ip, port, _, _, err := getTcpInfo(extra)
		if err != nil {
			return err
		}

		err = chi.TcpForward("local", ip, port)
		if err != nil {
			return err
		}
	case "forwarded-tcpip":
		if !chi.ci.ChkPerm("tcp") {
			close(chi.ch)
			return ErrNoPerms
		}

		chi.Type = "remote"
		chi.ch <- 1

		ip, port, _, _, err := getTcpInfo(extra)
		if err != nil {
			return err
		}

		err = chi.TcpForward("remote", ip, port)
		if err != nil {
			return err
		}
	case "auth-agent@openssh.com":
		if !chi.ci.ChkPerm("tcp") {
			close(chi.ch)
			return ErrNoPerms
		}

		chi.Type = "sshagent"
		chi.ch <- 1
	default:
		log.Error("channel type %s not supported.", chantype)
		err = ErrChanTypeNotSupported
	}
	return
}

func (chi *ChanInfo) serveReq(ch ssh.Channel, req *ssh.Request) (err error) {
	err = chi.onReq(req)
	if err != nil {
		log.Error("%s", err.Error())
		req.Reply(false, nil)
		return
	}

	r, err := ch.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		log.Error("%s", err.Error())
		req.Reply(false, nil)
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

func (ci *ChanInfo) serveReqs(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	log.Debug("chan reqs begin.")
	for req := range reqs {
		log.Debug("new chan req: %s(reply: %t, payload: %d).",
			req.Type, req.WantReply, len(req.Payload))
		err := ci.serveReq(ch, req)
		if err != nil {
			log.Error("%s", err.Error())
		}
	}
	log.Debug("chan reqs end.")
}

func (chi *ChanInfo) Serve(conn ssh.Conn, newChan ssh.NewChannel) (err error) {
	log.Info("new channel: %s (len: %d)",
		newChan.ChannelType(), len(newChan.ExtraData()))

	err = chi.onType(newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
		newChan.Reject(ssh.ResourceShortage, err.Error())
		log.Error("reject channel: %s", err.Error())
		return
	}

	chout, outreqs, err := conn.OpenChannel(
		newChan.ChannelType(), newChan.ExtraData())
	if err != nil {
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

	go chi.serveReqs(chin, outreqs)
	go chi.serveReqs(chout, inreqs)

	_, ok := <-chi.ch
	if !ok {
		return
	}

	switch chi.Type {
	case "local", "remote":
		go MultiCopyClose(chin, chout, &DebugStream{"out"})
		go MultiCopyClose(chout, chin, &DebugStream{"in"})
	case "sshagent":
		go MultiCopyClose(chin, chout, &DebugStream{"out"})
		go MultiCopyClose(chout, chin, &DebugStream{"in"})
	case "shell":
		out, err := chi.prepareFile("out", "")
		if err != nil {
			return err
		}
		go MultiCopyClose(chin, chout)
		go MultiCopyClose(chout, chin, out)
	case "exec":
		out, err := chi.prepareFile("out", strings.Join(chi.ExecCmds, "\r"))
		if err != nil {
			return err
		}
		go MultiCopyClose(chin, chout)
		go MultiCopyClose(chout, chin, out)
	case "scpto":
		go MultiCopyClose(chin, chout, CreateScpStream(chi))
		go MultiCopyClose(chout, chin)
	case "scpfrom":
		go MultiCopyClose(chin, chout)
		go MultiCopyClose(chout, chin, CreateScpStream(chi))
	default:
		// FIXME:
		log.Warning("redirect before setup")
	}
	return
}
