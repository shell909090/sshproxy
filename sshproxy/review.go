package sshproxy

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"
)

type LogReader struct {
	f *os.File
	b byte
	d time.Duration
	t time.Time
	l int
}

func CreateLogReader(filename string, b byte, d time.Duration) (lr *LogReader, err error) {
	f, err := os.Open(filename)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	log.Info("open %s for audit %d.", filename, b)

	lr = &LogReader{f: f, b: b, d: d}
	return
}

func (lr *LogReader) Close() (err error) {
	log.Info("close reader")
	lr.f.Close()
	return
}

func (lr *LogReader) Write(p []byte) (n int, err error) {
	for _, c := range p {
		i := bytes.Index([]byte("0123456789"), c)
		log.Debug("%d", i)
		n += 1
	}
	return
}

func (lr *LogReader) load() (err error) {
	var header [3]byte

	for lr.t.After(time.Now()) {
		time.Sleep(lr.t.Sub(time.Now()))
	}

	for {
		_, err = io.ReadFull(lr.f, header[:])
		if err != nil && err != io.EOF {
			log.Error("%s", err.Error())
		}
		if err != nil {
			return
		}

		b := header[0]
		l := binary.BigEndian.Uint16(header[1:])

		if b != lr.b {
			buf := make([]byte, l)
			_, err = io.ReadFull(lr.f, buf)
			if err != nil {
				log.Error("%s", err.Error())
				return
			}
			continue
		}

		// log.Debug("reader loaded %d.", l)
		lr.l += int(l)
		lr.t = time.Now().Add(lr.d)
		return
	}
	return
}

func (lr *LogReader) Read(p []byte) (n int, err error) {
	for lr.l <= 0 {
		err = lr.load()
		if err != nil {
			return
		}
	}

	if len(p) > lr.l {
		p = p[:lr.l]
	}

	n, err = lr.f.Read(p)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}

	lr.l -= n
	return
}

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

	go MultiCopyClose(ch, lr)
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
