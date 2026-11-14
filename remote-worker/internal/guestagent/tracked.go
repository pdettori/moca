package guestagent

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// The OS-independent parts of level 2, tracked processes (spec §7): each process's
// ring log, the table of tracked processes, and the allocator of their uids. The
// Linux handlers (process_start, list, logs, stop) are built on these.

// trackedLogCap is each tracked process's ring log: stdout and stderr combined, held in
// the agent's memory (global constraints).
const trackedLogCap = 4 << 20

// Ruling P5-R5 bounds what exited processes hold, since every lease End carries the
// whole table in one frame (MaxFrame) and each ring lives in agent memory: the table
// keeps at most trackedExitedKeep exited entries, evicting the oldest exited first, and
// an exited process's ring is trimmed to its last trackedExitedLogCap bytes.
const (
	trackedExitedKeep   = 8
	trackedExitedLogCap = 64 << 10
)

// ring keeps the last max bytes of a byte stream. It is an io.Writer, safe for the
// concurrent stdout and stderr drains of one process and a reader of its Tail.
// Memory grows with what was written, up to max, never past it.
type ring struct {
	mu  sync.Mutex
	max int
	// buf holds the bytes kept. While len(buf) < max nothing has been dropped and head
	// is 0; once full, buf is circular and the oldest byte is at head.
	buf  []byte
	head int
}

func newRing(max int) *ring { return &ring{max: max} }

// Write keeps p, dropping the oldest bytes past max. It never fails and always reports
// all of p written, so a drain never stops on it.
func (r *ring) Write(p []byte) (int, error) {
	n := len(p)
	if r.max <= 0 {
		return n, nil
	}
	if len(p) > r.max {
		p = p[len(p)-r.max:]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) < r.max {
		k := min(r.max-len(r.buf), len(p))
		if need := len(r.buf) + k; need > cap(r.buf) {
			// Grown by hand, not by append, so the capacity never passes max.
			nb := make([]byte, len(r.buf), min(max(2*cap(r.buf), need), r.max))
			copy(nb, r.buf)
			r.buf = nb
		}
		r.buf = append(r.buf, p[:k]...)
		p = p[k:]
	}
	for len(p) > 0 {
		k := copy(r.buf[r.head:], p)
		p = p[k:]
		r.head = (r.head + k) % r.max
	}
	return n, nil
}

// Tail returns a copy of the last lines lines held: a trailing newline ends the last
// line rather than starting an empty one, and an unterminated last line counts as a
// line. Asked for more lines than are held, it returns everything held; once the ring
// has dropped bytes, that first line may start mid-line. lines <= 0 returns nothing.
func (r *ring) Tail(lines int) []byte {
	if lines <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// The held bytes, oldest first, are a then b.
	a, b := r.buf[r.head:], r.buf[:r.head]
	total := len(a) + len(b)
	if total == 0 {
		return nil
	}
	last := a[len(a)-1]
	if len(b) > 0 {
		last = b[len(b)-1]
	}
	end := total // a newline before end starts a line
	if last == '\n' {
		end--
	}
	start := 0
	segs := [2]struct {
		s   []byte
		off int
	}{{b, len(a)}, {a, 0}}
search:
	for _, sg := range segs {
		seg := sg.s[:min(max(end-sg.off, 0), len(sg.s))]
		for {
			i := bytes.LastIndexByte(seg, '\n')
			if i < 0 {
				break
			}
			if lines--; lines == 0 {
				start = sg.off + i + 1
				break search
			}
			seg = seg[:i]
		}
	}
	return r.suffix(start)
}

// suffix copies the held bytes from logical offset start (0 is the oldest) to the end.
// The caller holds mu.
func (r *ring) suffix(start int) []byte {
	a, b := r.buf[r.head:], r.buf[:r.head]
	out := make([]byte, 0, len(a)+len(b)-start)
	if start < len(a) {
		out = append(out, a[start:]...)
		return append(out, b...)
	}
	return append(out, b[start-len(a):]...)
}

// shrink lowers the ring's cap to max, keeping the newest max bytes and freeing the
// rest. Later writes are held to the new cap. A max at or above the current cap is a
// no-op.
func (r *ring) shrink(max int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if max >= r.max {
		return
	}
	held := len(r.buf)
	r.buf = r.suffix(held - min(held, max)) // a fresh slice, cap == len <= max
	r.head, r.max = 0, max
}

// trackedEntry is one tracked process: its row in the table, plus what the handlers
// need and the host is not shown.
type trackedEntry struct {
	TrackedProcess
	UID int   // the tracked uid it runs as; the uidAllocator's to release
	Log *ring // its combined stdout and stderr
}

// trackedTable is the agent's table of tracked processes, oldest first. A running
// process's name is unique among the running ones; starting a name that only an exited
// entry holds replaces that entry. An exited entry otherwise stays, so the agent can
// read why it died (spec §7), until the lease ends or it is the oldest of more than
// trackedExitedKeep exited entries (ruling P5-R5, markExit). Ids are 1, 2, 3, … in
// start order, never reused within the agent's life.
type trackedTable struct {
	mu      sync.Mutex
	seq     uint64
	entries []*trackedEntry
}

// start applies the name and limit rules, then calls launch to start the process, and
// records it. maxRunning caps the running processes (SH_LEASE_MAX_PROCESSES); an exited
// one does not count. An empty name is allowed and never clashes.
//
// launch gets the new entry's id and ring, and returns the process's pid and uid. It
// runs without the table's lock, with the entry already in the table as running, so a
// markExit for the id that arrives while launch runs (the process died at once) is
// kept, and a concurrent start sees the name and the slot as taken. If launch fails the
// entry is removed and its error returned; an exited entry of the same name is kept.
func (t *trackedTable) start(name string, maxRunning int, launch func(id string, log *ring) (pid, uid int, err error)) (TrackedProcess, error) {
	t.mu.Lock()
	running := 0
	for _, e := range t.entries {
		if e.State != TrackedRunning {
			continue
		}
		if name != "" && e.Name == name {
			t.mu.Unlock()
			return TrackedProcess{}, fmt.Errorf("process_name_taken: %s", name)
		}
		running++
	}
	if running >= maxRunning {
		t.mu.Unlock()
		return TrackedProcess{}, fmt.Errorf("process_limit: %d running (SH_LEASE_MAX_PROCESSES)", maxRunning)
	}
	t.seq++
	e := &trackedEntry{
		TrackedProcess: TrackedProcess{
			ID: strconv.FormatUint(t.seq, 10), Name: name, State: TrackedRunning,
			StartedUnixMs: time.Now().UnixMilli(),
		},
		Log: newRing(trackedLogCap),
	}
	t.entries = append(t.entries, e)
	t.mu.Unlock()

	pid, uid, err := launch(e.ID, e.Log)

	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = removeEntries(t.entries, func(o *trackedEntry) bool {
		if o == e {
			return err != nil
		}
		return err == nil && name != "" && o.Name == name && o.State != TrackedRunning
	})
	if err != nil {
		return TrackedProcess{}, err
	}
	e.PID, e.UID = pid, uid
	return e.TrackedProcess, nil
}

func removeEntries(es []*trackedEntry, drop func(*trackedEntry) bool) []*trackedEntry {
	out := es[:0]
	for _, e := range es {
		if !drop(e) {
			out = append(out, e)
		}
	}
	clear(es[len(out):])
	return out
}

// lookup finds an entry by id, or else by name, and returns a copy of it. An id wins
// over a name: a process named "2" is found by its name only when no entry has id 2.
func (t *trackedTable) lookup(idOrName string) (trackedEntry, bool) {
	if idOrName == "" {
		return trackedEntry{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.entries {
		if e.ID == idOrName {
			return *e, true
		}
	}
	for _, e := range t.entries {
		if e.Name == idOrName {
			return *e, true
		}
	}
	return trackedEntry{}, false
}

// list returns the table's rows, oldest first. MemoryBytes is left 0: it is the
// caller's to read from each process's cgroup.
func (t *trackedTable) list() []TrackedProcess {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TrackedProcess, len(t.entries))
	for i, e := range t.entries {
		out[i] = e.TrackedProcess
	}
	return out
}

// markExit records that the process id exited: killed(signal) when signal > 0, else
// exited(code). Only a running entry changes, so a second report is ignored; so is an
// unknown id. Ruling P5-R5: the exited process's ring is trimmed to its last
// trackedExitedLogCap bytes, and past trackedExitedKeep exited entries the oldest
// exited one is evicted, ring and all. A running entry is never evicted.
func (t *trackedTable) markExit(id string, code, signal int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.entries {
		if e.ID != id || e.State != TrackedRunning {
			continue
		}
		if signal > 0 {
			e.State, e.Code = TrackedKilled, signal
		} else {
			e.State, e.Code = TrackedExited, code
		}
		e.Log.shrink(trackedExitedLogCap)
		t.evictExited()
		return
	}
}

// evictExited drops the oldest exited entries past trackedExitedKeep. The caller holds
// mu.
func (t *trackedTable) evictExited() {
	excess := -trackedExitedKeep
	for _, e := range t.entries {
		if e.State != TrackedRunning {
			excess++
		}
	}
	t.entries = removeEntries(t.entries, func(e *trackedEntry) bool {
		if excess <= 0 || e.State == TrackedRunning {
			return false
		}
		excess--
		return true
	})
}

// uidAllocator hands out the tracked uids base .. base+n-1, one per tracked process
// (spec §3.3). A uid is held from take until release, and take also skips any uid the
// caller reports populated: a tracked process's children can outlive it in its cgroup,
// and a new process under the same uid could then ptrace them. Uids are handed out in
// turn, so a released one is the last to be reused.
type uidAllocator struct {
	mu    sync.Mutex
	base  int
	n     int
	next  int // the index take starts searching at
	inUse map[int]bool
}

func newUIDAllocator(base, n int) *uidAllocator {
	return &uidAllocator{base: base, n: n, inUse: map[int]bool{}}
}

// take returns a free uid whose cgroup populated does not report populated, or an error
// when there is none. populated is called with the allocator's lock held.
func (a *uidAllocator) take(populated func(uid int) bool) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := 0; i < a.n; i++ {
		idx := (a.next + i) % a.n
		uid := a.base + idx
		if a.inUse[uid] || populated(uid) {
			continue
		}
		a.inUse[uid] = true
		a.next = (idx + 1) % a.n
		return uid, nil
	}
	return 0, fmt.Errorf("guest-agent: no free tracked uid: all %d from %d are in use or still populated", a.n, a.base)
}

// release returns uid to the pool. A uid outside the range, or not held, is ignored.
func (a *uidAllocator) release(uid int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.inUse, uid)
}

// user is the passwd name of a tracked uid, sbxp<n> for base+n, as the image's passwd
// lines name them (global constraints).
func (a *uidAllocator) user(uid int) string { return "sbxp" + strconv.Itoa(uid-a.base) }
