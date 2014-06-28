package term

import (
	"github.com/op/go-logging"
	"io"
	"strconv"
	"strings"
	"time"
)

var log = logging.MustGetLogger("")

func ReadUntilByte(ch chan byte, c byte) (buf []byte, err error) {
	for {
		b, ok := <-ch
		if !ok {
			return nil, io.EOF
		}
		buf = append(buf, b)
		if b == c {
			return buf, nil
		}
	}
	return
}

func ReadUntil(ch chan byte, f func(c byte) bool) (buf []byte, err error) {
	for {
		b, ok := <-ch
		if !ok {
			return nil, io.EOF
		}
		buf = append(buf, b)
		if f(b) {
			return buf, nil
		}
	}
	return
}

func MemsetRune(buf []byte, c byte) {
	for i, _ := range buf {
		buf[i] = c
	}
}

type Emu struct {
	t        *Term
	ch_cmd   chan string
	ch_out   chan byte
	ch_done  chan int
	ch_idle  <-chan time.Time
	title    string
	mode_alt int
	prompt   string
}

func CreateEmu(chcmd chan string, cols, rows int) (e *Emu) {
	e = &Emu{
		t:        CreateTerm(cols, rows),
		ch_cmd:   chcmd,
		ch_out:   make(chan byte, 100),
		ch_done:  make(chan int, 0),
		mode_alt: 0,
	}
	go e.run()
	return e
}

func (e *Emu) Close() error {
	close(e.ch_out)
	<-e.ch_done
	return nil
}

func (e *Emu) Write(p []byte) (n int, err error) {
	for _, c := range p {
		e.ch_out <- c
	}
	return len(p), nil
}

func (e *Emu) run() {
	var err error
	defer func() {
		e.ch_done <- 1
	}()

QUIT:
	for {
		if e.ch_idle == nil {
			select {
			case c := <-e.ch_out:
				err = e.proc_out(c)
			default:
				e.ch_idle = time.After(100 * time.Millisecond)
			}
		} else {
			select {
			case c, ok := <-e.ch_out:
				if !ok {
					break QUIT
				}
				err = e.proc_out(c)
			case <-e.ch_idle:
				err = e.on_idle()
			}
		}
		if err != nil {
			log.Error("%s", err.Error())
		}
	}
}

func (e *Emu) on_idle() (err error) {
	log.Debug("on idle")
	return nil
}

func (e *Emu) proc_out(c byte) (err error) {
	switch c {
	case 0x07: // BEL (0x07, ^G) beeps;
		break
	case 0x08:
		// BS (0x08, ^H) backspaces one column
		// (but not past the beginning of the line);
		if e.t.x > 0 {
			e.t.x--
		} else if e.t.y > 0 {
			e.t.y--
			e.t.x = e.t.cols - 1
		}
	case 0x09:
		// HT (0x09, ^I) goes to the next tab stop or to the end of the line
		// if there is no earlier tab stop;
		for e.t.x < e.t.cols-1 {
			e.t.termbuf[e.t.y][e.t.x] = ' '
			e.t.x++
			if e.t.x%8 == 0 {
				break
			}
		}
	case 0x0A, 0x0B, 0x0C:
		// LF (0x0A, ^J), VT (0x0B, ^K) and FF (0x0C, ^L) all give a linefeed,
		// and if LF/NL (new-line mode) is set also a carriage return;
		// FIXME: what the hell
		e.t.x = 0
		e.t.y++
		if e.t.y >= e.t.rows {
			e.t.ScrollUp()
		}
	case 0x0D: // CR (0x0D, ^M) gives a carriage return;
		if e.t.x == 0 && e.t.y > 0 {
			e.t.y--
		} else {
			e.t.x = 0
		}
	case 0x0E: // SO (0x0E, ^N) activates the G1 character set;
		_, ok := <-e.ch_out
		if !ok {
			return io.EOF
		}
		e.t.Clean()
	case 0x0F: // SI (0x0F, ^O) activates the G0 character set;
		_, ok := <-e.ch_out
		if !ok {
			return io.EOF
		}
		e.t.Clean()
	case 0x18, 0x1A: // CAN (0x18, ^X) and SUB (0x1A, ^Z) interrupt escape sequences;
		break
	case 0x1B: // ESC (0x1B, ^[) starts an escape sequence;
		nc := <-e.ch_out
		switch nc {
		case '[':
			err = e.do_CSI()
			if err != nil {
				return
			}
		case ']':
			err = e.do_OSC()
			if err != nil {
				return
			}
		case '(', ')', '*', '+', '-', '.', '/':
			_, ok := <-e.ch_out
			if !ok {
				return io.EOF
			}
			e.t.Clean()
		case '=': // Application Keypad (DECKPAM).
			e.mode_alt = 1
		case '>': // Normal Keypad (DECKPNM).
			if e.mode_alt != 0 {
				e.t.x = 0
				e.t.y = 0
				e.t.Clean()
			}
			e.mode_alt = 0
		case 'E':
			break // Next line (CR+Index)
		case 'M':
			break // Reverse index (cursor up with scroll down when at margin)
		case 'D':
			break // Index (cursor down with scroll up when at margin)
		case 'c':
			break // tty reset
		}
	case 0x7f: // DEL (0x7F) is ignored;
		break
	case 0x9B: // CSI (0x9B) is equivalent to ESC [.
		err = e.do_CSI()
		if err != nil {
			return
		}
	default:
		// FIXME: insert mode?
		e.t.WriteOne(c)
	}
	return
}

func ParseOneParamInt(cmd []byte, dft int) (n int) {
	if len(cmd) <= 1 {
		return dft
	}
	n, err := strconv.Atoi(string(cmd[:len(cmd)-1]))
	if err != nil {
		n = dft
	}
	return
}

func ParseParamsInt(cmd []byte, dft int) (ns []int) {
	var n int
	var err error
	if len(cmd) <= 1 {
		return nil
	}

	for _, p := range strings.Split(string(cmd[:len(cmd)-1]), ";") {
		if len(p) != 0 {
			n, err = strconv.Atoi(p)
			if err != nil {
				n = dft
			}
		} else {
			n = dft
		}
		ns = append(ns, n)
	}
	return
}

func (e *Emu) do_CSI() (err error) {
	cmd, err := ReadUntil(e.ch_out, func(c byte) bool {
		return !(c >= '0' && c <= '9') && c != ';' && c != '?'
	})
	if err != nil {
		return
	}
	log.Debug("CSI: %s", string(cmd))
	switch cmd[len(cmd)-1] {
	case '@': // insert char
		// TODO:
		break
	case 'h': // set mode
		break
	case 'l': // clear mode
		break
	case 'm': // SGR – Select Graphic Rendition
		break
	case 'r': // set scroll window
		break
	case 'A': // move cursor up
		e.t.y -= ParseOneParamInt(cmd, 1)
		e.t.CursorRound()
	case 'B': // move cursor down
		e.t.y += ParseOneParamInt(cmd, 1)
		e.t.CursorRound()
	case 'C': // move cursor right
		e.t.x += ParseOneParamInt(cmd, 1)
		e.t.CursorRound()
	case 'D': // move cursor left
		e.t.x -= ParseOneParamInt(cmd, 1)
		e.t.CursorRound()
	case 'E': // move cursor down and to column 1
		e.t.y += ParseOneParamInt(cmd, 1)
		e.t.x = 0
		e.t.CursorRound()
	case 'F': // move cursor up and to column 1
		e.t.y -= ParseOneParamInt(cmd, 1)
		e.t.x = 0
		e.t.CursorRound()
	case 'G': // move cursor to column in current row
		e.t.x = ParseOneParamInt(cmd, 0)
		if e.t.x >= e.t.cols {
			e.t.x = e.t.cols - 1
		}
	case 'H':
		// CUP – Cursor Position
		// move cursor to row, column -> don't want to support absolute movement
		ns := ParseParamsInt(cmd, 0)
		if ns == nil {
			ns = []int{0, 0}
		}
		e.t.y = ns[0]
		e.t.x = ns[1]
		e.t.CursorRound()
	case 'J':
		// ED – Erase Data
		// erase display, treat it single-line because we only have this
		// TODO:
		// switch(ParseOneParamInt(cmd, 0)) {
		// case 0: // to the end
		// 	MemsetRune(e.t.termbuf[e.t.y][e.t.x:])
		// case 1: // from the beginning
		// 	MemsetRune(e.t.termbuf[e.t.y][:e.t.x])
		// case 2: // the whole
		// 	e.t.Clean()
		// 	// TODO: clean prompt line
		// }
	case 'K': // erase line
		switch ParseOneParamInt(cmd, 0) {
		case 0: // to the end
			MemsetRune(e.t.termbuf[e.t.y][e.t.x:], 0)
		case 1: // from the beginning
			l := e.t.termbuf[e.t.y]
			copy(l[:e.t.cols-e.t.x], l[e.t.x:])
			MemsetRune(l[e.t.cols-e.t.x:], 0)
		case 2: // the whole
			MemsetRune(e.t.termbuf[e.t.y], 0)
		}
	case 'P': // delete char
		// TODO:
		break
	case 'M', 'S': // SU – Scroll Up, scroll up -> N/A in vt102?
		e.t.ScrollUp()
	case 'L', 'T': // SD – Scroll Down, scroll down -> N/A in vt102?
		e.t.ScrollDown()
	case 'X': // erase chars (replace to \0) -> useful for our case?
		break
	case 0x18, 0x1A: // CAN (0x18, ^X) and SUB (0x1A, ^Z) interrupt escape sequences;
		break
	default:
		log.Warning("CSI: %s", string(cmd))
	}
	return
}

func (e *Emu) do_OSC() (err error) {
	// FIXME: error process

	_, err = ReadUntilByte(e.ch_out, ';')
	if err != nil {
		return
	}
	title, _ := ReadUntilByte(e.ch_out, 0x07)
	e.title = strings.TrimRight(string(title), "\x07")
	log.Info("title: %s", e.title)
	return
}

func (e *Emu) proc_in(c byte) {

}
