package sshproxy

import (
	"code.google.com/p/go.crypto/ssh"
	"encoding/binary"
	"errors"
	"github.com/op/go-logging"
	"io"
	"io/ioutil"
)

var (
	ErrScpStreamIllegal     = errors.New("scp stream illegal")
	ErrChanTypeNotSupported = errors.New("channel type not support")
	ErrIllegalUserName      = errors.New("illegal username")
	ErrIllegalPubkey        = errors.New("illegal pubkey")
	ErrSCSNotFound          = errors.New("ssh conn server not found")
	ErrHostKey              = errors.New("host key not match")
	ErrDataBase             = errors.New("database error")
)

var log = logging.MustGetLogger("")

func LoadPrivateKey(filename string) (private ssh.Signer, err error) {
	log.Info("load private key: %s", filename)

	privateBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error("failed to load keyfile: %s", err.Error())
		return
	}
	private, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Error("failed to parse keyfile: %s", err.Error())
		return
	}
	return
}

func MultiCopyClose(s io.Reader, ds ...io.WriteCloser) (err error) {
	var ws []io.Writer
	for _, d := range ds {
		ws = append(ws, d.(io.Writer))
		defer d.Close()
	}
	_, err = io.Copy(io.MultiWriter(ws...), s)
	if err != nil && err != io.EOF {
		log.Error("%s", err.Error())
	}
	return
}

func ReadPayloadString(payload []byte) (s string, rest []byte, err error) {
	size := binary.BigEndian.Uint32(payload[:4])
	s = string(payload[4 : 4+size])
	rest = payload[4+size:]
	return
}

func ReadPayloadUint32(payload []byte) (i uint32, rest []byte, err error) {
	i = binary.BigEndian.Uint32(payload[:4])
	rest = payload[4:]
	return
}

func ReadPayloads(payload []byte) (strs []string, err error) {
	var s string
	for len(payload) >= 4 {
		s, payload, err = ReadPayloadString(payload)
		if err != nil {
			return
		}
		strs = append(strs, s)
	}
	return
}

func getTcpInfo(d []byte) (srcip string, srcport uint32, dstip string, dstport uint32, err error) {
	srcip, d, err = ReadPayloadString(d)
	if err != nil {
		return
	}
	srcport, d, err = ReadPayloadUint32(d)
	if err != nil {
		return
	}
	dstip, d, err = ReadPayloadString(d)
	if err != nil {
		return
	}
	dstport, d, err = ReadPayloadUint32(d)
	if err != nil {
		return
	}
	return
}

type DebugStream struct {
	Name string
}

func (ds *DebugStream) Write(p []byte) (n int, err error) {
	log.Debug("%s write(%d): %v", ds.Name, len(p), p)
	return len(p), nil
}

func (ds *DebugStream) Close() error {
	return nil
}
