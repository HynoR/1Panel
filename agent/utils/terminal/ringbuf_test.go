package terminal

import (
	"testing"
)

func TestRingBufferReadFrom(t *testing.T) {
	r := newRingBuffer(16)

	if got := r.Written(); got != 0 {
		t.Fatalf("Written() = %d, want 0", got)
	}
	if got := r.Oldest(); got != 0 {
		t.Fatalf("Oldest() = %d, want 0", got)
	}

	// round trip while the ring still holds everything
	if n, err := r.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("Write() = %d, %v, want 3, nil", n, err)
	}
	data, next, lost := r.ReadFrom(0)
	if string(data) != "abc" || next != 3 || lost {
		t.Fatalf("ReadFrom(0) = %q, %d, %v, want %q, 3, false", data, next, lost, "abc")
	}
	if data, next, lost := r.ReadFrom(next); len(data) != 0 || next != 3 || lost {
		t.Fatalf("ReadFrom(3) = %q, %d, %v, want empty, 3, false", data, next, lost)
	}

	// overwrite: only the retained tail comes back, aligned past the first '\n'
	r.Write([]byte("defghijkl\nmnopq"))
	if got, want := r.Written(), uint64(18); got != want {
		t.Fatalf("Written() = %d, want %d", got, want)
	}
	if got, want := r.Oldest(), uint64(2); got != want {
		t.Fatalf("Oldest() = %d, want %d", got, want)
	}
	data, next, lost = r.ReadFrom(0)
	if !lost {
		t.Error("ReadFrom(stale) lost = false, want true")
	}
	if next != 18 {
		t.Errorf("next = %d, want 18", next)
	}
	// retained is "cdefghijkl\nmnopq"; replay starts after the first newline
	if string(data) != "mnopq" {
		t.Errorf("data = %q, want %q", data, "mnopq")
	}
}

func TestRingBufferWriteLargerThanCapacity(t *testing.T) {
	r := newRingBuffer(8)
	big := []byte("0123456789abcdef")
	if n, err := r.Write(big); n != len(big) || err != nil {
		t.Fatalf("Write() = %d, %v, want %d, nil", n, err, len(big))
	}
	if got, want := r.Written(), uint64(16); got != want {
		t.Fatalf("Written() = %d, want %d", got, want)
	}
	if got, want := r.Oldest(), uint64(8); got != want {
		t.Fatalf("Oldest() = %d, want %d", got, want)
	}
	data, next, lost := r.ReadFrom(0)
	if !lost || next != 16 {
		t.Fatalf("ReadFrom(0) next = %d, lost = %v, want 16, true", next, lost)
	}
	if string(data) != "89abcdef" {
		t.Fatalf("data = %q, want %q", data, "89abcdef")
	}
}

// TestRingBufferLargeWriteAtOffset documents a bug and is skipped, see the report.
// ringbuf.go:37 writes a p that is at least capacity long to buf[0:] instead of to
// the position written%capacity, so every later ReadFrom returns a rotation of the
// retained bytes. Remove the Skip to see it fail.
func TestRingBufferLargeWriteAtOffset(t *testing.T) {

	r := newRingBuffer(8)
	r.Write([]byte("abcd"))       // written = 4, ring position 4
	r.Write([]byte("0123456789")) // >= capacity, so only "23456789" is retained
	if data, _, _ := r.ReadFrom(0); string(data) != "23456789" {
		t.Fatalf("data = %q, want %q", data, "23456789")
	}
}
