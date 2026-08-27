package terminal

import (
	"bytes"
	"strings"
	"testing"
)

func TestRingBufferWriteAndSnapshot(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
		writes   []string
		wantLen  int
		want     string
	}{
		{
			name:     "empty",
			capacity: 16,
			want:     "",
		},
		{
			name:     "single write below capacity",
			capacity: 16,
			writes:   []string{"abc"},
			wantLen:  3,
			want:     "abc",
		},
		{
			name:     "multiple writes below capacity",
			capacity: 16,
			writes:   []string{"ab", "cd", "ef"},
			wantLen:  6,
			want:     "abcdef",
		},
		{
			name:     "exact capacity keeps everything",
			capacity: 4,
			writes:   []string{"abcd"},
			wantLen:  4,
			want:     "abcd",
		},
		{
			name:     "wrap drops oldest up to newline",
			capacity: 8,
			writes:   []string{"12\n45678", "9a"},
			wantLen:  8,
			want:     "456789a",
		},
		{
			name:     "wrap without newline keeps everything",
			capacity: 4,
			writes:   []string{"abcd", "ef"},
			wantLen:  4,
			want:     "cdef",
		},
		{
			name:     "write larger than capacity keeps newest",
			capacity: 4,
			writes:   []string{"abcdefgh"},
			wantLen:  4,
			want:     "efgh",
		},
		{
			name:     "write larger than capacity trims to newline",
			capacity: 6,
			writes:   []string{"abcdef\nghi"},
			wantLen:  6,
			want:     "ghi",
		},
		{
			name:     "wrap over segmented writes",
			capacity: 6,
			writes:   []string{"abc", "de\n", "fgh"},
			wantLen:  6,
			want:     "fgh",
		},
		{
			name:     "zero length write is ignored",
			capacity: 6,
			writes:   []string{"ab", "", "cd"},
			wantLen:  4,
			want:     "abcd",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRingBuffer(tc.capacity)
			for _, w := range tc.writes {
				n, err := r.Write([]byte(w))
				if err != nil {
					t.Fatalf("Write(%q) returned error: %v", w, err)
				}
				if n != len(w) {
					t.Fatalf("Write(%q) = %d, want %d", w, n, len(w))
				}
			}
			if got := r.Len(); got != tc.wantLen {
				t.Errorf("Len() = %d, want %d", got, tc.wantLen)
			}
			if got := string(r.Snapshot()); got != tc.want {
				t.Errorf("Snapshot() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRingBufferDefaultCapacity(t *testing.T) {
	for _, capacity := range []int{0, -1} {
		r := newRingBuffer(capacity)
		if len(r.buf) != defaultRingSize {
			t.Fatalf("newRingBuffer(%d) capacity = %d, want %d", capacity, len(r.buf), defaultRingSize)
		}
	}
}

func TestRingBufferSnapshotIsACopy(t *testing.T) {
	r := newRingBuffer(8)
	if _, err := r.Write([]byte("abcd")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	snapshot := r.Snapshot()
	snapshot[0] = 'z'
	if got := string(r.Snapshot()); got != "abcd" {
		t.Fatalf("Snapshot() = %q, want %q", got, "abcd")
	}
}

func TestRingBufferReset(t *testing.T) {
	r := newRingBuffer(4)
	if _, err := r.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	r.Reset()
	if r.Len() != 0 {
		t.Fatalf("Len() after Reset = %d, want 0", r.Len())
	}
	if snapshot := r.Snapshot(); snapshot != nil {
		t.Fatalf("Snapshot() after Reset = %q, want nil", snapshot)
	}
	if _, err := r.Write([]byte("xy")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if got := string(r.Snapshot()); got != "xy" {
		t.Fatalf("Snapshot() = %q, want %q", got, "xy")
	}
}

func TestRingBufferLargeStream(t *testing.T) {
	r := newRingBuffer(1024)
	var all bytes.Buffer
	for i := range 500 {
		chunk := strings.Repeat("x", i%17) + "\n"
		all.WriteString(chunk)
		if _, err := r.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
	}
	if r.Len() != 1024 {
		t.Fatalf("Len() = %d, want 1024", r.Len())
	}
	snapshot := r.Snapshot()
	if len(snapshot) == 0 || len(snapshot) >= 1024 {
		t.Fatalf("len(Snapshot()) = %d, want between 1 and 1023", len(snapshot))
	}
	if !bytes.HasSuffix(all.Bytes(), snapshot) {
		t.Fatal("Snapshot() is not a suffix of the written stream")
	}
}
