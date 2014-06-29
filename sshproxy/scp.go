package sshproxy

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

type ScpStream struct {
	ci      *ConnInfo
	ignores int
}

func CreateScpStream(ci *ConnInfo) (ss *ScpStream) {
	return &ScpStream{ci: ci}
}

func (ss *ScpStream) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		switch {
		case bytes.Compare(p, []byte{0}) == 0:
			return 1, nil
		case ss.ignores == 0:
			if p[0] != 'C' {
				err = ErrScpStreamIllegal
				log.Error("%s", err.Error())
				return
			}

			meta := strings.SplitN(string(p[1:]), " ", 3)

			var size int
			size, err = strconv.Atoi(meta[1])
			if err != nil {
				log.Error("%s", err.Error())
				return
			}

			ss.ci.on_file_transmit(strings.Trim(meta[2], "\r\n"), size)
			ss.ignores = size
			return len(p), nil
		default:
			l := len(p)
			if l > ss.ignores {
				l = ss.ignores
			}
			p = p[l:]
			ss.ignores -= l
			n += l
		}
	}
	return
}

func (ss *ScpStream) Close() error {
	return nil
}
