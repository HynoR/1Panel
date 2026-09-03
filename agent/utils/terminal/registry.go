package terminal

import "sync"

// sessions is the process wide registry of live sessions, keyed by id.
// Open stores, Close deletes.
var sessions sync.Map

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
