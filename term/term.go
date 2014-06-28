package term

type Term struct {
	termbuf    [][]rune
	x, y       int
	rows, cols int
}

func CreateTerm(cols, rows int) (t *Term) {
	t = &Term{
		x:    0,
		y:    0,
		rows: rows,
		cols: cols,
	}
	t.Clean()
	return t
}

func (t *Term) Clean() {
	t.termbuf = make([][]rune, t.rows)
	for i, _ := range t.termbuf {
		t.termbuf[i] = make([]rune, t.cols)
	}
}

func (t *Term) GetCursor() (x, y int) {
	return t.x, t.y
}

func (t *Term) GetSize() (x, y int) {
	return t.rows, t.cols
}

func (t *Term) ScrollUp() {
	log.Debug("scroll up")
	t.y--
	t.termbuf = t.termbuf[1:]
	t.termbuf = append(t.termbuf, make([]rune, t.cols))
}

func (t *Term) ScrollDown() {
	log.Debug("scroll down")
	t.y++
	copy(t.termbuf[1:], t.termbuf[:len(t.termbuf)-1])
	t.termbuf[0] = make([]rune, t.cols)
}

func (t *Term) CursorRound() {
	if t.y >= t.rows {
		t.y = t.rows - 1
	} else if t.y < 0 {
		t.y = 0
	}
	if t.x >= t.cols {
		t.x = t.cols - 1
	} else if t.x < 0 {
		t.x = 0
	}
}

func (t *Term) Dump(w io.Writer) {
	for _, l := range t.termbuf {
		w.Write([]byte(string(l)))
		w.Write([]byte{'\n'})
	}
}

func (t *Term) Write(p []byte) (n int, err error) {
	for _, c := range p {
		t.WriteOne(c)
	}
	return len(p), nil
}

func (t *Term) WriteOne(b byte) error {
	t.termbuf[t.y][t.x] = b
	t.x += 1
	if t.x >= t.cols {
		t.x = 0
		t.y += 1
	}
	if t.y >= t.rows {
		t.ScrollUp()
	}
	return nil
}

func (t *Term) WriteString(s string) (int, error) {
	return t.Write([]byte(s))
}
