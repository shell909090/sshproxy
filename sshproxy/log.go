package sshproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Logger struct {
	*os.File
	mu  sync.Mutex
	cnt int32
}

func CreateLogger(basedir string, t time.Time, id int) (l *Logger, err error) {
	logdir := fmt.Sprintf("%s/%s", basedir, t.Format("20060102"))
	err = os.MkdirAll(logdir, 0755)
	if err != nil {
		return
	}

	f, err := os.OpenFile(fmt.Sprintf("%s/%d.rec", logdir, id),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return
	}

	l = &Logger{File: f}
	return
}

type SubLogger struct {
	*Logger
	b   byte
	buf *bytes.Buffer
	mu  sync.Mutex
	t   time.Time
}

func (l *Logger) CreateSubLogger(b byte) (sl *SubLogger) {
	atomic.AddInt32(&l.cnt, 1)
	return &SubLogger{
		Logger: l,
		b:      b,
		buf:    bytes.NewBuffer(nil),
	}
}

func (sl *SubLogger) ForceWrite(p []byte) (n int, err error) {
	var l int
	var buf [3]byte

	for len(p) > 0 {
		l = len(p)
		if l > 65535 {
			l = 65535
		}
		buf[0] = sl.b
		binary.BigEndian.PutUint16(buf[1:], uint16(l))

		sl.Logger.mu.Lock()
		_, err = sl.Logger.Write(buf[:])
		if err != nil {
			sl.Logger.mu.Unlock()
			return
		}

		l, err = sl.Logger.Write(p[:l])
		if err != nil {
			sl.Logger.mu.Unlock()
			return
		}
		sl.Logger.mu.Unlock()

		p = p[l:]
		n += l
	}
	return
}

func (sl *SubLogger) Write(p []byte) (n int, err error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if time.Now().Before(sl.t) {
		return sl.buf.Write(p)
	}

	n, err = sl.ForceWrite(sl.buf.Bytes())
	if err != nil {
		return
	}
	sl.buf.Reset()

	n, err = sl.ForceWrite(p)
	if err != nil {
		return
	}

	sl.t = time.Now().Add(QUANTUM_SLICE)
	return
}

func (sl *SubLogger) Close() (err error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	_, err = sl.ForceWrite(sl.buf.Bytes())
	if err != nil {
		return
	}
	sl.buf.Reset()

	n := atomic.AddInt32(&sl.Logger.cnt, -1)
	if n == 0 {
		return sl.Logger.Close()
	}
	return
}

type LogReader struct {
	f  *os.File
	b  byte
	d  time.Duration
	pr io.ReadCloser
	pw io.WriteCloser
}

func CreateLogReader(filename string, b byte, d time.Duration) (lr *LogReader, err error) {
	f, err := os.Open(filename)
	if err != nil {
		log.Error("%s", err.Error())
		return
	}
	log.Info("open %s for audit %d.", filename, b)

	pr, pw := io.Pipe()
	lr = &LogReader{f: f, b: b, d: d, pr: pr, pw: pw}
	go lr.Loop()
	return
}

func (lr *LogReader) Close() (err error) {
	log.Info("close reader")
	lr.f.Close()
	lr.pr.Close()
	lr.pw.Close()
	return
}

func (lr *LogReader) Loop() {
	var header [3]byte
LOOP:
	for {
		_, err := io.ReadFull(lr.f, header[:])
		switch err {
		case io.EOF:
			break LOOP
		case nil:
		default:
			log.Error("%s", err.Error())
			return
		}

		b := header[0]
		l := binary.BigEndian.Uint16(header[1:])

		buf := make([]byte, l)
		_, err = io.ReadFull(lr.f, buf)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}

		if b != lr.b {
			continue
		}

		_, err = lr.pw.Write(buf)
		if err != nil {
			log.Error("%s", err.Error())
			return
		}

		time.Sleep(lr.d)
	}
}

func (lr *LogReader) Read(p []byte) (n int, err error) {
	return lr.pr.Read(p)
}
