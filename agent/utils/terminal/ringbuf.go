package terminal

import (
	"bytes"
	"sync"
)

// defaultRingSize is the default capacity of a session output ring buffer.
const defaultRingSize = 256 * 1024

// ringBuffer is a fixed capacity byte ring buffer. Writes never fail: once the
// buffer is full the oldest bytes are dropped to make room for the newest ones.
type ringBuffer struct {
	mu      sync.Mutex
	buf     []byte
	start   int  // index of the oldest byte
	size    int  // number of bytes currently stored
	wrapped bool // true once at least one byte has been dropped
}

func newRingBuffer(capacity int) *ringBuffer {
	if capacity <= 0 {
		capacity = defaultRingSize
	}
	return &ringBuffer{buf: make([]byte, capacity)}
}

// Write appends p, dropping the oldest bytes when the capacity is exceeded.
// It always reports len(p) written and never returns an error.
func (r *ringBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	capacity := len(r.buf)
	if n >= capacity {
		if n > capacity || r.size > 0 {
			r.wrapped = true
		}
		copy(r.buf, p[n-capacity:])
		r.start = 0
		r.size = capacity
		return n, nil
	}

	end := (r.start + r.size) % capacity
	written := copy(r.buf[end:], p)
	if written < n {
		copy(r.buf, p[written:])
	}
	if r.size+n > capacity {
		r.wrapped = true
		r.start = (r.start + (r.size + n - capacity)) % capacity
		r.size = capacity
	} else {
		r.size += n
	}
	return n, nil
}

// Snapshot returns a copy of the buffered bytes, oldest first. When bytes have
// already been dropped the result starts right after the first '\n' so that a
// replay never begins in the middle of an escape sequence or a multi byte rune.
// If there is no '\n' at all the whole content is returned.
func (r *ringBuffer) Snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size == 0 {
		return nil
	}
	out := make([]byte, r.size)
	n := copy(out, r.buf[r.start:min(r.start+r.size, len(r.buf))])
	if n < r.size {
		copy(out[n:], r.buf[:r.size-n])
	}
	if !r.wrapped {
		return out
	}
	if idx := bytes.IndexByte(out, '\n'); idx >= 0 {
		return out[idx+1:]
	}
	return out
}

// Len returns the number of buffered bytes.
func (r *ringBuffer) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Reset drops every buffered byte.
func (r *ringBuffer) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.start = 0
	r.size = 0
	r.wrapped = false
}
