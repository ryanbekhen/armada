package volbackup

import (
	"errors"
	"io"
)

// Chunk sizes: boundaries come from a gear rolling hash over the content,
// so an insertion moves only the boundaries next to it.
const (
	minChunk = 512 << 10
	maxChunk = 8 << 20
	// chunkMask gives boundaries about every 2 MiB after minChunk.
	chunkMask = 1<<21 - 1
)

// chunker cuts a stream into content-defined chunks.
type chunker struct {
	r    io.Reader
	gear *[256]uint64
	buf  []byte
	n    int // bytes in buf
	eof  bool
}

func newChunker(r io.Reader, gear *[256]uint64) *chunker {
	return &chunker{r: r, gear: gear, buf: make([]byte, maxChunk)}
}

// next returns the next chunk, valid until the following call, or io.EOF.
func (c *chunker) next() ([]byte, error) {
	for !c.eof && c.n < maxChunk {
		m, err := c.r.Read(c.buf[c.n:])
		c.n += m
		if errors.Is(err, io.EOF) {
			c.eof = true
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if c.n == 0 {
		return nil, io.EOF
	}
	cut := c.n
	if c.n > minChunk {
		var h uint64
		for i := minChunk; i < c.n; i++ {
			h = h<<1 + c.gear[c.buf[i]]
			if h&chunkMask == 0 {
				cut = i + 1
				break
			}
		}
	}
	out := make([]byte, cut)
	copy(out, c.buf[:cut])
	copy(c.buf, c.buf[cut:c.n])
	c.n -= cut
	return out, nil
}
