package guestagent

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// ringReference is what a ring of capacity max must hold after the writes: the last max
// bytes of their concatenation.
func ringReference(all []byte, max int) []byte {
	if len(all) > max {
		return all[len(all)-max:]
	}
	return all
}

// tailReference is Tail's contract, written the slow way: split into lines (a trailing
// newline ends the last line rather than starting an empty one), keep the last n.
func tailReference(held []byte, n int) []byte {
	if n <= 0 || len(held) == 0 {
		return nil
	}
	lines := strings.SplitAfter(string(held), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	return []byte(strings.Join(lines, ""))
}

func TestRingCapIs4MiB(t *testing.T) {
	if trackedLogCap != 4<<20 {
		t.Fatalf("trackedLogCap = %d, want 4 MiB (global constraints)", trackedLogCap)
	}
}

// 8-byte lines, so the 4 MiB cap holds exactly 524288 whole lines.
func numberedLines(from, to int) []byte {
	var b bytes.Buffer
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "%07d\n", i)
	}
	return b.Bytes()
}

func TestRingKeepsTheLast4MiBAndTailsAtTheCap(t *testing.T) {
	const perCap = trackedLogCap / 8 // 524288 lines fill the ring exactly
	r := newRing(trackedLogCap)

	// Exactly at the cap: nothing is dropped.
	all := numberedLines(0, perCap)
	for off := 0; off < len(all); off += 32 << 10 {
		_, _ = r.Write(all[off:min(off+32<<10, len(all))])
	}
	if got := r.Tail(perCap + 10); !bytes.Equal(got, all) {
		t.Fatalf("at the cap: Tail(more than held) returned %d bytes, want all %d", len(got), len(all))
	}
	if got := r.Tail(perCap); !bytes.Equal(got, all) {
		t.Fatalf("at the cap: Tail(%d) returned %d bytes, want %d", perCap, len(got), len(all))
	}
	if got := string(r.Tail(1)); got != fmt.Sprintf("%07d\n", perCap-1) {
		t.Fatalf("at the cap: Tail(1) = %q", got)
	}

	// One more MiB: the oldest MiB goes, whole lines, since 1 MiB is a multiple of 8.
	more := numberedLines(perCap, perCap+perCap/4)
	_, _ = r.Write(more)
	want := ringReference(append(all, more...), trackedLogCap)
	if !bytes.HasPrefix(want, []byte(fmt.Sprintf("%07d\n", perCap/4))) {
		t.Fatalf("test arithmetic: held data starts %q", want[:8])
	}
	if got := r.Tail(perCap); !bytes.Equal(got, want) {
		t.Fatalf("past the cap: Tail(%d) returned %d bytes, want the last 4 MiB", perCap, len(got))
	}
	if got := r.Tail(perCap - 1); !bytes.Equal(got, want[8:]) {
		t.Fatalf("past the cap: Tail(%d) is not the held data less its first line", perCap-1)
	}
	if got := string(r.Tail(2)); got != fmt.Sprintf("%07d\n%07d\n", perCap+perCap/4-2, perCap+perCap/4-1) {
		t.Fatalf("past the cap: Tail(2) = %q", got)
	}

	// Three bytes more: the held data now starts in the middle of a line, which Tail
	// returns as it is, a cut first line.
	_, _ = r.Write([]byte("xyz"))
	want = ringReference(append(append(all, more...), "xyz"...), trackedLogCap)
	if got := r.Tail(perCap + 1); !bytes.Equal(got, want) {
		t.Fatalf("cut first line: Tail(%d) returned %d bytes, want %d", perCap+1, len(got), len(want))
	}
	if got := string(r.Tail(1)); got != "xyz" {
		t.Fatalf("Tail(1) = %q, want the unterminated last line", got)
	}
}

func TestRingTailLineCounts(t *testing.T) {
	cases := []struct {
		data string
		n    int
		want string
	}{
		{"", 3, ""},
		{"a\nb\nc\n", 0, ""},
		{"a\nb\nc\n", -1, ""},
		{"a\nb\nc\n", 1, "c\n"},
		{"a\nb\nc\n", 2, "b\nc\n"},
		{"a\nb\nc\n", 3, "a\nb\nc\n"},
		{"a\nb\nc\n", 4, "a\nb\nc\n"},
		{"a\nb\nc", 1, "c"},
		{"a\nb\nc", 2, "b\nc"},
		{"\n\n\n", 2, "\n\n"},
		{"no newline", 1, "no newline"},
	}
	for _, c := range cases {
		r := newRing(64)
		_, _ = r.Write([]byte(c.data))
		if got := string(r.Tail(c.n)); got != c.want {
			t.Errorf("Tail(%d) of %q = %q, want %q", c.n, c.data, got, c.want)
		}
	}
}

func TestRingWriteLargerThanTheCapKeepsItsEnd(t *testing.T) {
	r := newRing(8)
	n, err := r.Write([]byte("0123456789abcdef"))
	if n != 16 || err != nil {
		t.Fatalf("Write = %d, %v; want every byte accepted", n, err)
	}
	if got := string(r.Tail(5)); got != "89abcdef" {
		t.Fatalf("Tail = %q, want the last 8 bytes", got)
	}
}

// Random write sizes against small caps, so the wrap lands at every offset.
func TestRingMatchesTheReferenceAcrossWraps(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, max := range []int{1, 2, 7, 16, 61} {
		r := newRing(max)
		var all []byte
		for i := 0; i < 400; i++ {
			p := make([]byte, rng.Intn(2*max+2))
			for j := range p {
				p[j] = "ab\n"[rng.Intn(3)]
			}
			if n, err := r.Write(p); n != len(p) || err != nil {
				t.Fatalf("Write = %d, %v", n, err)
			}
			all = append(all, p...)
			held := ringReference(all, max)
			for _, n := range []int{1, 2, 3, max, max + 1} {
				if got, want := r.Tail(n), tailReference(held, n); !bytes.Equal(got, want) {
					t.Fatalf("cap %d, write %d: Tail(%d) = %q, want %q", max, i, n, got, want)
				}
			}
		}
	}
}

func TestRingNeverHoldsMoreThanItsCap(t *testing.T) {
	r := newRing(1000)
	for i := 0; i < 50; i++ {
		_, _ = r.Write(make([]byte, 333))
	}
	if c := cap(r.buf); c > 1000 {
		t.Fatalf("ring buffer capacity %d, over the 1000-byte cap", c)
	}
}

// launchOK is a launch that starts nothing, so the table can be tested alone.
func launchOK(pid, uid int) func(string, *ring) (int, int, error) {
	return func(string, *ring) (int, int, error) { return pid, uid, nil }
}

func mustStart(t *testing.T, tt *trackedTable, name string, max, pid int) TrackedProcess {
	t.Helper()
	p, err := tt.start(name, max, launchOK(pid, 20000))
	if err != nil {
		t.Fatalf("start %q: %v", name, err)
	}
	return p
}

func TestTrackedNameTakenByARunningProcessIsRefused(t *testing.T) {
	var tt trackedTable
	mustStart(t, &tt, "web", 4, 100)
	launched := false
	_, err := tt.start("web", 4, func(string, *ring) (int, int, error) { launched = true; return 101, 20001, nil })
	if err == nil || err.Error() != "process_name_taken: web" {
		t.Fatalf("err = %v, want process_name_taken: web", err)
	}
	if launched {
		t.Fatal("a refused start launched its process")
	}
	if n := len(tt.list()); n != 1 {
		t.Fatalf("list has %d entries, want 1", n)
	}
}

func TestTrackedNameHeldOnlyByAnExitedEntryIsReplaced(t *testing.T) {
	var tt trackedTable
	old := mustStart(t, &tt, "web", 4, 100)
	other := mustStart(t, &tt, "db", 4, 101)
	tt.markExit(old.ID, 1, 0)
	nu := mustStart(t, &tt, "web", 4, 102)
	if nu.ID == old.ID {
		t.Fatalf("the replacement reused id %s", nu.ID)
	}
	got := tt.list()
	if len(got) != 2 || got[0].ID != other.ID || got[1].ID != nu.ID {
		t.Fatalf("list = %+v, want db then the new web", got)
	}
	if _, ok := tt.lookup(old.ID); ok {
		t.Fatal("the replaced entry is still found by its id")
	}
}

func TestTrackedFailedLaunchKeepsTheExitedEntry(t *testing.T) {
	var tt trackedTable
	old := mustStart(t, &tt, "web", 4, 100)
	tt.markExit(old.ID, 0, 0)
	_, err := tt.start("web", 4, func(string, *ring) (int, int, error) { return 0, 0, errors.New("fork failed") })
	if err == nil || err.Error() != "fork failed" {
		t.Fatalf("err = %v, want the launch's error", err)
	}
	got := tt.list()
	if len(got) != 1 || got[0].ID != old.ID || got[0].State != TrackedExited {
		t.Fatalf("list = %+v, want only the old, exited web", got)
	}
}

func TestTrackedUnnamedProcessesNeverClash(t *testing.T) {
	var tt trackedTable
	a := mustStart(t, &tt, "", 4, 100)
	b := mustStart(t, &tt, "", 4, 101)
	if a.ID == b.ID {
		t.Fatalf("two starts share id %s", a.ID)
	}
	if n := len(tt.list()); n != 2 {
		t.Fatalf("list has %d entries, want 2", n)
	}
}

func TestTrackedLimitCountsRunningOnly(t *testing.T) {
	var tt trackedTable
	a := mustStart(t, &tt, "a", 2, 100)
	mustStart(t, &tt, "b", 2, 101)
	_, err := tt.start("c", 2, launchOK(102, 20002))
	if err == nil || err.Error() != "process_limit: 2 running (SH_LEASE_MAX_PROCESSES)" {
		t.Fatalf("err = %v, want process_limit: 2 running (SH_LEASE_MAX_PROCESSES)", err)
	}
	tt.markExit(a.ID, 0, 0)
	mustStart(t, &tt, "c", 2, 102)
	if n := len(tt.list()); n != 3 {
		t.Fatalf("list has %d entries, want 3 (the exited a is kept)", n)
	}
}

func TestTrackedLookupByIDOrName(t *testing.T) {
	var tt trackedTable
	web := mustStart(t, &tt, "web", 4, 100)
	tt.markExit(web.ID, 0, 0)
	db := mustStart(t, &tt, "db", 4, 101)

	for _, key := range []string{db.ID, "db"} {
		e, ok := tt.lookup(key)
		if !ok || e.ID != db.ID || e.PID != 101 || e.UID != 20000 || e.Log == nil {
			t.Fatalf("lookup(%q) = %+v, %v", key, e, ok)
		}
	}
	if e, ok := tt.lookup("web"); !ok || e.ID != web.ID || e.State != TrackedExited {
		t.Fatalf("lookup(web) = %+v, %v; want the exited entry", e, ok)
	}
	for _, key := range []string{"", "nope", "999"} {
		if _, ok := tt.lookup(key); ok {
			t.Fatalf("lookup(%q) found an entry", key)
		}
	}
}

func TestTrackedMarkExitStates(t *testing.T) {
	var tt trackedTable
	before := time.Now().UnixMilli()
	a := mustStart(t, &tt, "a", 4, 100)
	b := mustStart(t, &tt, "b", 4, 101)
	after := time.Now().UnixMilli()
	if a.State != TrackedRunning || a.PID != 100 || a.StartedUnixMs < before || a.StartedUnixMs > after {
		t.Fatalf("started entry = %+v", a)
	}
	tt.markExit(a.ID, 3, 0)
	tt.markExit(b.ID, 0, 9)
	tt.markExit("999", 0, 0) // unknown: ignored
	got := tt.list()
	if got[0].State != TrackedExited || got[0].Code != 3 {
		t.Fatalf("a = %+v, want exited(3)", got[0])
	}
	if got[1].State != TrackedKilled || got[1].Code != 9 {
		t.Fatalf("b = %+v, want killed(9)", got[1])
	}
	// A second exit report for the same entry changes nothing.
	tt.markExit(a.ID, 0, 15)
	if e, _ := tt.lookup(a.ID); e.State != TrackedExited || e.Code != 3 {
		t.Fatalf("a after a second markExit = %+v", e)
	}
}

// The reaper can report an exit while launch is still running (the process died at
// once): the entry must already exist, so the exit is not lost.
func TestTrackedExitDuringLaunchIsKept(t *testing.T) {
	var tt trackedTable
	p, err := tt.start("quick", 4, func(id string, _ *ring) (int, int, error) {
		tt.markExit(id, 0, 9)
		return 100, 20000, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := tt.lookup(p.ID); e.State != TrackedKilled || e.Code != 9 || e.PID != 100 {
		t.Fatalf("entry = %+v, want killed(9) with its pid", e)
	}
}

func TestTrackedLaunchGetsTheEntryRing(t *testing.T) {
	var tt trackedTable
	p, err := tt.start("w", 4, func(_ string, log *ring) (int, int, error) {
		_, _ = log.Write([]byte("hello\n"))
		return 100, 20000, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := tt.lookup(p.ID)
	if got := string(e.Log.Tail(1)); got != "hello\n" {
		t.Fatalf("Tail = %q", got)
	}
}

func TestUIDAllocatorRefusesAtMax(t *testing.T) {
	a := newUIDAllocator(20000, 4)
	none := func(int) bool { return false }
	seen := map[int]bool{}
	for i := 0; i < 4; i++ {
		uid, err := a.take(none)
		if err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		if uid < 20000 || uid > 20003 || seen[uid] {
			t.Fatalf("take %d = %d: out of range or a repeat (%v)", i, uid, seen)
		}
		seen[uid] = true
	}
	if uid, err := a.take(none); err == nil {
		t.Fatalf("a fifth take returned %d", uid)
	}
	a.release(20002)
	if uid, err := a.take(none); err != nil || uid != 20002 {
		t.Fatalf("take after release = %d, %v; want 20002", uid, err)
	}
}

func TestUIDAllocatorSkipsPopulatedUIDs(t *testing.T) {
	a := newUIDAllocator(20000, 4)
	populated := map[int]bool{20000: true, 20002: true}
	for i := 0; i < 10; i++ {
		uid, err := a.take(func(u int) bool { return populated[u] })
		if err != nil {
			t.Fatal(err)
		}
		if populated[uid] {
			t.Fatalf("take handed out %d, whose cgroup is populated", uid)
		}
		a.release(uid)
	}
	all := func(int) bool { return true }
	if uid, err := a.take(all); err == nil {
		t.Fatalf("take returned %d with every uid populated", uid)
	}
}

// Fresh: a released uid is not the next one handed out while another is free.
func TestUIDAllocatorRotates(t *testing.T) {
	a := newUIDAllocator(20000, 3)
	none := func(int) bool { return false }
	var got []int
	for i := 0; i < 4; i++ {
		uid, err := a.take(none)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, uid)
		a.release(uid)
	}
	if fmt.Sprint(got) != "[20000 20001 20002 20000]" {
		t.Fatalf("uids = %v, want each in turn", got)
	}
	a.release(12345) // outside the range: ignored
}

func TestUIDAllocatorUserNames(t *testing.T) {
	a := newUIDAllocator(20000, 4)
	for uid, want := range map[int]string{20000: "sbxp0", 20003: "sbxp3"} {
		if got := a.user(uid); got != want {
			t.Errorf("user(%d) = %q, want %q", uid, got, want)
		}
	}
}

func TestUIDAllocatorWithNoUIDsRefuses(t *testing.T) {
	a := newUIDAllocator(20000, 0)
	if uid, err := a.take(func(int) bool { return false }); err == nil {
		t.Fatalf("take returned %d from an empty range", uid)
	}
}

func TestTrackedExitedBoundsAreTheRuling(t *testing.T) {
	if trackedExitedKeep != 8 || trackedExitedLogCap != 64<<10 {
		t.Fatalf("trackedExitedKeep %d, trackedExitedLogCap %d; want 8 and 64 KiB (ruling P5-R5)", trackedExitedKeep, trackedExitedLogCap)
	}
}

// Ruling P5-R5: at most trackedExitedKeep exited entries are kept; a 9th exit evicts the
// oldest exited entry, ring and all, and never a running one, however old.
func TestTrackedNinthExitEvictsTheOldestExited(t *testing.T) {
	var tt trackedTable
	var running, exited []string
	for i := 0; i < trackedExitedKeep+1; i++ {
		if i%3 == 0 { // running entries interleaved, the first older than every exited one
			running = append(running, mustStart(t, &tt, fmt.Sprintf("r%d", i), 100, 1000+i).ID)
		}
		e := mustStart(t, &tt, fmt.Sprintf("e%d", i), 100, 2000+i)
		exited = append(exited, e.ID)
		tt.markExit(e.ID, 0, 0)
	}
	if _, ok := tt.lookup(exited[0]); ok {
		t.Fatal("the oldest exited entry survived the 9th exit")
	}
	var gotRunning, gotExited []string
	for _, p := range tt.list() {
		if p.State == TrackedRunning {
			gotRunning = append(gotRunning, p.ID)
		} else {
			gotExited = append(gotExited, p.ID)
		}
	}
	if fmt.Sprint(gotRunning) != fmt.Sprint(running) {
		t.Fatalf("running ids %v, want every running one kept: %v", gotRunning, running)
	}
	if fmt.Sprint(gotExited) != fmt.Sprint(exited[1:]) {
		t.Fatalf("exited ids %v, want the newest %d: %v", gotExited, trackedExitedKeep, exited[1:])
	}
}

// Ruling P5-R5: at exit the ring is trimmed to its last 64 KiB, and stays bounded by
// that for what the process's leftovers still write.
func TestTrackedExitTrimsTheRingToItsTail(t *testing.T) {
	var tt trackedTable
	p := mustStart(t, &tt, "chatty", 4, 100)
	e, _ := tt.lookup(p.ID)
	all := numberedLines(0, (1<<20)/8) // 1 MiB of 8-byte lines
	_, _ = e.Log.Write(all)
	tt.markExit(p.ID, 0, 0)

	e, _ = tt.lookup(p.ID)
	held := e.Log.Tail(len(all))
	if len(held) != trackedExitedLogCap || !bytes.Equal(held, all[len(all)-trackedExitedLogCap:]) {
		t.Fatalf("exited ring holds %d bytes, want the last %d", len(held), trackedExitedLogCap)
	}
	if c := cap(e.Log.buf); c > trackedExitedLogCap {
		t.Fatalf("exited ring capacity %d, over %d", c, trackedExitedLogCap)
	}
	_, _ = e.Log.Write([]byte("late\n"))
	held = e.Log.Tail(len(all))
	if len(held) != trackedExitedLogCap || !bytes.HasSuffix(held, []byte("late\n")) {
		t.Fatalf("after a late write the ring holds %d bytes ending %q", len(held), held[len(held)-5:])
	}
	if c := cap(e.Log.buf); c > trackedExitedLogCap {
		t.Fatalf("exited ring capacity %d after a late write, over %d", c, trackedExitedLogCap)
	}
}

func TestTrackedExitTrimKeepsASmallRingWhole(t *testing.T) {
	var tt trackedTable
	p := mustStart(t, &tt, "quiet", 4, 100)
	e, _ := tt.lookup(p.ID)
	_, _ = e.Log.Write([]byte("a\nb\n"))
	tt.markExit(p.ID, 1, 0)
	if e, _ = tt.lookup(p.ID); string(e.Log.Tail(10)) != "a\nb\n" {
		t.Fatalf("Tail = %q", e.Log.Tail(10))
	}
}

// The table at its cap, MAX running (4) plus trackedExitedKeep exited, every field at its
// widest, still fits one End frame. Names are 255 bytes of '<', which encoding/json
// writes as <, six bytes each: the worst case for a 255-byte name.
func TestTrackedEndAtTheCapFitsAFrame(t *testing.T) {
	var tt trackedTable
	name := func(i int) string { return fmt.Sprintf("%03d", i) + strings.Repeat("<", 252) }
	const maxRunning = 4
	for i := 0; i < trackedExitedKeep+3; i++ {
		e := mustStart(t, &tt, name(i), maxRunning, 1<<22)
		tt.markExit(e.ID, 0, 1<<30)
	}
	for i := 0; i < maxRunning; i++ {
		mustStart(t, &tt, name(100+i), maxRunning, 1<<22)
	}
	end := End{ExitCode: -1 << 31, DroppedStdout: 1 << 62, DroppedStderr: 1 << 62, TeardownFailed: true, Tracked: tt.list()}
	if len(end.Tracked) != maxRunning+trackedExitedKeep {
		t.Fatalf("table holds %d entries, want %d", len(end.Tracked), maxRunning+trackedExitedKeep)
	}
	for i := range end.Tracked {
		end.Tracked[i].Code, end.Tracked[i].StartedUnixMs, end.Tracked[i].MemoryBytes = -1<<62, -1<<62, -1<<62
		end.Tracked[i].ID = "18446744073709551615"
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, KindEnd, end); err != nil {
		t.Fatalf("the End at the cap does not fit a frame: %v", err)
	}
	t.Logf("End at the cap: %d of %d bytes", buf.Len()-5, MaxFrame)
}
