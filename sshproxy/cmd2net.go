package sshproxy

import (
	"fmt"
	"io"
	"net"
	"os/exec"
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

type CmdNet struct {
	w      Waiter
	c      io.Closer
	name   string
	stdin  io.WriteCloser
	stdout io.Reader
}

func RunCmdNet(name string, arg ...string) (cn *CmdNet, err error) {
	return CreateCmdNet(exec.Command(name, arg...))
}

func CreateCmdNet(cmd *exec.Cmd) (cn *CmdNet, err error) {
	cn = &CmdNet{
		w:    cmd,
		name: fmt.Sprintf("pid:%d", cmd.Process.Pid),
	}
	cn.stdin, err = cmd.StdinPipe()
	if err != nil {
		return
	}
	cn.stdout, err = cmd.StdoutPipe()
	if err != nil {
		return
	}
	return
}

func (cn *CmdNet) Read(b []byte) (n int, err error) {
	return cn.stdout.Read(b)
}

func (cn *CmdNet) Write(b []byte) (n int, err error) {
	return cn.stdin.Write(b)
}

func (cn *CmdNet) Close() error {
	cn.stdin.Close()
	if cn.c != nil {
		defer cn.c.Close()
	}
	return cn.w.Wait()
}

func (cn *CmdNet) LocalAddr() net.Addr {
	return &Addr{name: cn.name}
}

func (cn *CmdNet) RemoteAddr() net.Addr {
	return &Addr{name: cn.name}
}

func (cn *CmdNet) SetDeadline(t time.Time) error {
	return nil
}

func (cn *CmdNet) SetReadDeadline(t time.Time) error {
	return nil
}

func (cn *CmdNet) SetWriteDeadline(t time.Time) error {
	return nil
}
