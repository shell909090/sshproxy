package sshproxy

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"time"
)

type CmdNet struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func RunCmdNet(name string, arg ...string) (cn *CmdNet, err error) {
	cmd := exec.Command(name, arg...)
	cn, err = CreateCmdNet(cmd)
	if err != nil {
		return
	}
	return
}

func CreateCmdNet(cmd *exec.Cmd) (cn *CmdNet, err error) {
	cn = &CmdNet{cmd: cmd}
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
	return cn.cmd.Wait()
}

func (cn *CmdNet) LocalAddr() net.Addr {
	return &Addr{cn: cn}
}

func (cn *CmdNet) RemoteAddr() net.Addr {
	return &Addr{cn: cn}
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

type Addr struct {
	cn *CmdNet
}

func (a *Addr) Network() string {
	return "cmd"
}

func (a *Addr) String() string {
	return fmt.Sprintf("%d", a.cn.cmd.Process.Pid)
}
