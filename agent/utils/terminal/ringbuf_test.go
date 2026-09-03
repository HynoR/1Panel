package terminal

import (
	"bytes"
	"testing"
)

func TestRingBufferWriteReadFrom(t *testing.T) {
	tests := []struct {
		name   string
		writes [][]byte
		from   uint64
		want   []byte
		next   uint64
		lost   bool
	}{
		{
			name:   "round trip",
			writes: [][]byte{[]byte("hello world")},
			from:   0,
			want:   []byte("hello world"),
			next:   11,
		},
		{
			name:   "incremental read returns only the tail",
			writes: [][]byte{[]byte("hello "), []byte("world")},
			from:   6,
			want:   []byte("world"),
			next:   11,
		},
		{
			name:   "empty write is a no-op",
			writes: [][]byte{[]byte("abc"), {}},
			from:   0,
			want:   []byte("abc"),
			next:   3,
		},
		{
			name:   "read at written returns nothing",
			writes: [][]byte{[]byte("abc")},
			from:   3,
			want:   nil,
			next:   3,
		},
		{
			name:   "offset beyond written clamps",
			writes: [][]byte{[]byte("abc")},
			from:   9999,
			want:   nil,
			next:   3,
		},
		{
			name:   "empty buffer",
			writes: nil,
			from:   0,
			want:   nil,
			next:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRingBuffer()
			for _, w := range tt.writes {
				n, err := r.Write(w)
				if err != nil {
					t.Fatalf("Write(%q) error: %v", w, err)
				}
				if n != len(w) {
					t.Fatalf("Write(%q) = %d, want %d", w, n, len(w))
				}
			}
			got, next, lost := r.ReadFrom(tt.from)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("data = %q, want %q", got, tt.want)
			}
			if next != tt.next {
				t.Errorf("next = %d, want %d", next, tt.next)
			}
			if lost != tt.lost {
				t.Errorf("lost = %v, want %v", lost, tt.lost)
			}
		})
	}
}

// A read spanning the capacity boundary must stitch both halves back together.
func TestRingBufferWrapAround(t *testing.T) {
	r := newRingBuffer()
	head := bytes.Repeat([]byte("a"), ringSize-5)
	if _, err := r.Write(head); err != nil {
		t.Fatalf("Write head: %v", err)
	}
	tail := []byte("0123456789abcdefghij") // 20 bytes, straddles the boundary
	if _, err := r.Write(tail); err != nil {
		t.Fatalf("Write tail: %v", err)
	}

	got, next, lost := r.ReadFrom(uint64(len(head)))
	if !bytes.Equal(got, tail) {
		t.Errorf("data = %q, want %q", got, tail)
	}
	if want := uint64(ringSize + 15); next != want {
		t.Errorf("next = %d, want %d", next, want)
	}
	if lost {
		t.Error("lost = true, want false: the tail was still retained")
	}
}

// A reader whose offset was overwritten is told so, and resumes on a line boundary.
func TestRingBufferLostReaderResumesAfterNewline(t *testing.T) {
	r := newRingBuffer()
	data := bytes.Repeat([]byte("x"), ringSize+10) // oldest becomes 10
	data[15] = '\n'
	if _, err := r.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := r.Oldest(), uint64(10); got != want {
		t.Fatalf("Oldest() = %d, want %d", got, want)
	}

	got, next, lost := r.ReadFrom(0)
	if !lost {
		t.Error("lost = false, want true")
	}
	if want := data[16:]; !bytes.Equal(got, want) {
		t.Errorf("data len = %d, want %d (must start just after the newline)", len(got), len(want))
	}
	if want := uint64(ringSize + 10); next != want {
		t.Errorf("next = %d, want %d", next, want)
	}
}

// A single oversized write keeps only the tail, and offsets stay absolute.
func TestRingBufferOversizedWriteKeepsTail(t *testing.T) {
	r := newRingBuffer()
	data := bytes.Repeat([]byte("y"), ringSize+100) // no '\n': nothing is trimmed
	n, err := r.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Write = %d, want %d", n, len(data))
	}
	if got, want := r.Oldest(), uint64(100); got != want {
		t.Fatalf("Oldest() = %d, want %d", got, want)
	}

	got, next, lost := r.ReadFrom(100)
	if lost {
		t.Error("lost = true, want false: reading exactly from the oldest byte")
	}
	if len(got) != ringSize {
		t.Errorf("data len = %d, want %d", len(got), ringSize)
	}
	if want := uint64(ringSize + 100); next != want {
		t.Errorf("next = %d, want %d", next, want)
	}
}
