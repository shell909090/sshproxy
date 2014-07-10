package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"net/url"
	"time"
)

type ReviewInfo struct {
	srv          *Server
	Username     string
	RecordLogsId int
	filename     string
}

func (ri *ReviewInfo) init() (err error) {
	v := &url.Values{}
	v.Add("username", ri.Username)
	v.Add("recordlogid", fmt.Sprintf("%d", ri.RecordLogsId))

	type ReviewRslt struct {
		Access bool
		Time   string
	}
	rslt := &ReviewRslt{}

	err = ri.srv.GetJson("/l/rev", false, v, rslt)
	if err != nil {
		return
	}

	Starttime, err := time.Parse("2006-01-02T15:04:05", rslt.Time)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	if !rslt.Access {
		return ErrNoPerms
	}
	ri.filename = fmt.Sprintf("%s/%s/%d.rec",
		ri.srv.WebConfig.Logdir, Starttime.Format("20060102"), ri.RecordLogsId)
	return
}

func (ri *ReviewInfo) serveChan(ch ssh.Channel, reqs <-chan *ssh.Request) {
	go AcceptRequests(reqs)
	log.Info("review chan begin.")

	lr, err := CreateLogReader(ri.filename, 02, QUANTUM_SLICE)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	defer lr.Close()

	MultiCopyClose(lr, ch)
	log.Info("review chan end.")
	return
}

func (ri *ReviewInfo) Serve(srvConn *ssh.ServerConn, srvChans <-chan ssh.NewChannel, srvReqs <-chan *ssh.Request) (err error) {
	go ssh.DiscardRequests(srvReqs)
	log.Info("review connect begin.")

	for newChan := range srvChans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.ResourceShortage, "not session")
			continue
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			log.Error("%s", err.Error())
			continue
		}
		go ri.serveChan(ch, reqs)
	}
	log.Info("review connect closed.")
	return
}
