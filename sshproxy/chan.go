package sshproxy

type ChanInfo struct {
	ci        *ConnInfo
	Type      string
	RemoteDir string
	ExecCmds  []string
}

func CreateChanInfo(ci *ConnInfo) (chi *ChanInfo) {
	chi := &ChanInfo{
		ci:   ci,
		Type: "unknown",
	}
	return chi
}

func (ci *ConnInfo) prepareFile(ext, cmd string) (w io.WriteCloser, err error) {
	starttime, err := ci.getStarttime()
	if err != nil {
		return
	}

	logDir := fmt.Sprintf("%s/%s", ci.srv.LogDir, starttime.Format("20060102"))
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		return
	}

	RecordLogsId, err := ci.insertRecordLogs(ci.Type, cmd, "", 0)
	if err != nil {
		return
	}

	w, err = os.OpenFile(fmt.Sprintf("%s/%d.%s", logDir, RecordLogsId, ext),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	return
}

func (ci *ConnInfo) onTcpForward(direct, ip string, port uint32) (err error) {
	log.Notice("mapping %s port to %s:%d", direct, ip, port)
	_, err = ci.insertRecordLogs(ci.Type, ip, "", int(port))
	return
}

func (ci *ConnInfo) onFileTransmit(filename string, size int) (id int64, err error) {
	log.Notice("%s with name: %s, size: %d, remote dir: %s",
		ci.Type, filename, size, ci.RemoteDir)
	id, err = ci.insertRecordLogs(ci.Type, filename, ci.RemoteDir, size)
	return
}

func (ci *ConnInfo) onFileData(b []byte) (err error) {
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

		switch cmds[0] {
		case "scp":
			switch cmds[len(cmds)-2] {
			case "-t":
				ci.Type = "scpto"
			case "-f":
				ci.Type = "scpfrom"
			default:
				ci.Type = "unknown"
			}
			ci.ch_ready <- 1
			ci.RemoteDir = cmds[len(cmds)-1]
			log.Info("session in %s mode, remote dir: %s.",
				ci.Type, ci.RemoteDir)
		default:
			ci.Type = "exec"
			ci.ch_ready <- 1
			ci.ExecCmds = append(ci.ExecCmds, strs[0])
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

func (ci *ChanInfo) onChanType(chantype string, extra []byte) (err error) {
	switch chantype {
	case "session":
	case "direct-tcpip":
		ci.Type = "local"

		ip, port, _, _, err := getTcpInfo(extra)
		if err != nil {
			return err
		}

		err = ci.onTcpForward("local", ip, port)
		if err != nil {
			return err
		}
	case "forwarded-tcpip":
		ci.Type = "remote"

		ip, port, _, _, err := getTcpInfo(extra)
		if err != nil {
			return err
		}

		err = ci.onTcpForward("remote", ip, port)
		if err != nil {
			return err
		}
	case "auth-agent@openssh.com":
		ci.Type = "sshagent"
	default:
		log.Error("channel type %s not supported.", chantype)
		err = ErrChanTypeNotSupported
	}
	return
}

func (ci *ConnInfo) serveReq(ch ssh.Channel, req *ssh.Request) (err error) {
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

func (ci *ChanInfo) ServeReqs(ch ssh.Channel, reqs <-chan *ssh.Request) {
	log.Debug("chan reqs begin.")
	for req := range reqs {
		log.Debug("new chan req: %s(reply: %t, payload: %d).",
			req.Type, req.WantReply, len(req.Payload))
		err := ci.ServeReq(ch, req)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}
	}
	log.Debug("chan reqs end.")
}

func (ci *ChanInfo) Serve(conn ssh.Conn, newChan ssh.NewChannel) (err error) {
	log.Debug("new channel: %s (len: %d)",
		newChan.ChannelType(), len(newChan.ExtraData()))

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

	go ci.serveReqs(chin, outreqs)
	go ci.serveReqs(chout, inreqs)

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
		go MultiCopyClose(chin, chout, CreateScpStream(ci))
		go MultiCopyClose(chout, chin)
	case "scpfrom":
		go MultiCopyClose(chin, chout)
		go MultiCopyClose(chout, chin, CreateScpStream(ci))
	default:
		// FIXME:
	}
	return
}
