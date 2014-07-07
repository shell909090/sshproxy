package sshproxy

import (
	"io"
	"net"
	"time"
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
