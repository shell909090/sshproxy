package sshproxy

import (
	"bytes"
	"strconv"
	"strings"
)

type FileRecorder interface {
	FileTransmit(string, int) error
	FileData([]byte) error
}

type ScpStream struct {
	fr      FileRecorder
	ignores int
}

func CreateScpStream(fr FileRecorder) (ss *ScpStream) {
	return &ScpStream{fr: fr}
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

			err = ss.fr.FileTransmit(strings.Trim(meta[2], "\r\n"), size)
			if err != nil {
				return
			}
			ss.ignores = size
			return len(p), nil
		default:
			l := len(p)
			if l > ss.ignores {
				l = ss.ignores
			}
			err = ss.fr.FileData(p[:l])
			if err != nil {
				return
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
