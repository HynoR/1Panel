package terminal

import "sync"

// sessions is the process wide registry of live sessions, keyed by id.
var sessions sync.Map

// register adds s and removes it again once it closes.
func register(s *Session) {
	sessions.Store(s.ID, s)
	s.onClosed = func() { sessions.Delete(s.ID) }
}

// Lookup resolves id for owner. Foreign and unknown sessions look the same.
func Lookup(id, owner string) (*Session, bool) {
	v, ok := sessions.Load(id)
	if !ok {
		return nil, false
	}
	s := v.(*Session)
	if s.Owner != "" && owner != "" && s.Owner != owner {
		return nil, false
	}
	return s, true
}
