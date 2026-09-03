package terminal

import (
	"testing"
	"time"
)

// newTestSession builds a registry entry without a backend. Never Close() these.
func newTestSession(t *testing.T, id, owner, title string, hostID uint, createdAt time.Time) *Session {
	t.Helper()
	s := &Session{
		ID:        id,
		Owner:     owner,
		Title:     title,
		HostID:    hostID,
		CreatedAt: createdAt,
		done:      make(chan struct{}),
	}
	sessions.Store(id, s)
	t.Cleanup(func() { sessions.Delete(id) })
	return s
}

func TestLookup(t *testing.T) {
	newTestSession(t, "sess-lookup", "alice", "shell", 7, time.Now())

	tests := []struct {
		name  string
		id    string
		owner string
		want  bool
	}{
		{name: "owner sees its own session", id: "sess-lookup", owner: "alice", want: true},
		{name: "empty owner sees any session", id: "sess-lookup", owner: "", want: true},
		{name: "another owner sees nothing", id: "sess-lookup", owner: "bob", want: false},
		{name: "unknown id", id: "sess-missing", owner: "alice", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ok := Lookup(tt.id, tt.owner)
			if ok != tt.want {
				t.Fatalf("Lookup(%q, %q) ok = %v, want %v", tt.id, tt.owner, ok, tt.want)
			}
			if ok && s.ID != tt.id {
				t.Errorf("Lookup returned session %q, want %q", s.ID, tt.id)
			}
			if !ok && s != nil {
				t.Errorf("Lookup returned %v alongside ok=false, want nil", s)
			}
		})
	}
}

func TestListIsOwnerScopedAndOrdered(t *testing.T) {
	base := time.Now().Add(-time.Hour)
	newTestSession(t, "sess-b", "alice", "second", 2, base.Add(2*time.Minute))
	newTestSession(t, "sess-a", "alice", "first", 1, base.Add(time.Minute))
	newTestSession(t, "sess-c", "bob", "other", 3, base.Add(3*time.Minute))

	got := List("alice")
	if len(got) != 2 {
		t.Fatalf("List(alice) returned %d sessions, want 2: %+v", len(got), got)
	}

	want := []Info{
		{ID: "sess-a", Title: "first", HostID: 1},
		{ID: "sess-b", Title: "second", HostID: 2},
	}
	for i, w := range want {
		if got[i].ID != w.ID {
			t.Errorf("session %d id = %q, want %q (oldest first)", i, got[i].ID, w.ID)
		}
		if got[i].Title != w.Title {
			t.Errorf("session %d title = %q, want %q", i, got[i].Title, w.Title)
		}
		if got[i].HostID != w.HostID {
			t.Errorf("session %d hostID = %d, want %d", i, got[i].HostID, w.HostID)
		}
		if got[i].Attached {
			t.Errorf("session %d attached = true, want false", i)
		}
		if got[i].CreatedAt.IsZero() {
			t.Errorf("session %d createdAt is zero", i)
		}
	}
	if !got[0].CreatedAt.Before(got[1].CreatedAt) {
		t.Errorf("sessions are not ordered by CreatedAt ascending: %v then %v", got[0].CreatedAt, got[1].CreatedAt)
	}
}

func TestCloseSessionUnknownID(t *testing.T) {
	if err := CloseSession("sess-nope", "alice"); err == nil {
		t.Fatal("CloseSession on an unknown id returned nil, want an error")
	}
}
