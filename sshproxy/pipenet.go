package sshproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"text/template"
	"time"

	"golang.org/x/crypto/ssh"
)

type Waiter interface {
	Wait() error
}

type Addr struct {
	name string
}

func (a *Addr) Network() string {
	return "cmd"
}

func (a *Addr) String() string {
	return a.name
}

type PipeNet struct {
	wa   Waiter
	c    io.Closer
	name string
	w    io.WriteCloser
	r    io.Reader
}

func (pn *PipeNet) Read(b []byte) (n int, err error) {
	return pn.r.Read(b)
}

func (pn *PipeNet) Write(b []byte) (n int, err error) {
	return pn.w.Write(b)
}

func (pn *PipeNet) Close() error {
	pn.w.Close()
	if pn.c != nil {
		defer pn.c.Close()
	}
	return pn.wa.Wait()
}

func (pn *PipeNet) LocalAddr() net.Addr {
	return &Addr{name: pn.name}
}

func (pn *PipeNet) RemoteAddr() net.Addr {
	return &Addr{name: pn.name}
}

func (pn *PipeNet) SetDeadline(t time.Time) error {
	return nil
}

func (pn *PipeNet) SetReadDeadline(t time.Time) error {
	return nil
}

func (pn *PipeNet) SetWriteDeadline(t time.Time) error {
	return nil
}

func createPipeNet(client *ssh.Client, cmd string) (pn *PipeNet, err error) {
	session, err := client.NewSession()
	if err != nil {
		return
	}

	pn = &PipeNet{
		wa:   session,
		c:    client,
		name: "ssh",
	}

	pn.w, err = session.StdinPipe()
	if err != nil {
		return
	}
	pn.r, err = session.StdoutPipe()
	if err != nil {
		return
	}

	err = session.Start(cmd)
	return
}

func fmtCmd(proxycommand, desthost string, destport int) (cmd string, err error) {
	if proxycommand != "" {
		tmpl, err := template.New("test").Parse(proxycommand)
		if err != nil {
			return "", err
		}

		parameter := map[string]interface{}{
			"host": desthost,
			"port": destport,
		}

		buf := bytes.NewBuffer(nil)
		err = tmpl.Execute(buf, parameter)
		if err != nil {
			return "", err
		}
		cmd = buf.String()
	} else {
		cmd = fmt.Sprintf("nc %s %d", desthost, destport)
	}
	return
}
