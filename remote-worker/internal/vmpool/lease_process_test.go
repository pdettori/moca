package vmpool

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/rossoctl/moca/gen/go/sandbox/v1"
)

// Level 2 in the pool (plan 5, Task 5): process-kind routing, the tracked mirror, process
// lists on lease events and status, and the lease_process audit records.

// processFeatures is a level-2 snapshot's manifest features.
var processFeatures = []string{FeatureLeaseV1, FeatureLeaseProcessesV1}

// processPool is leasePool on a snapshot advertising lease-processes-v1.
func processPool(t *testing.T) (*pool, *leaseLauncher, *fakeClock) {
	t.Helper()
	return leasePool(t, func(c *Config) { c.ManifestFeatures = processFeatures })
}

// processPoolOn is leasePoolOn on a level-2 snapshot: a second process over the same disk.
func processPoolOn(t *testing.T, root string, clk *fakeClock) (*pool, *leaseLauncher) {
	t.Helper()
	plentyOfHostMemory(t)
	lc := newLeaseLauncher()
	p, err := New(Config{
		VMM:               lc.Kind(),
		SnapshotDir:       t.TempDir(),
		WorkspaceRoot:     root,
		MaxRuns:           16,
		MaxCommittedBytes: 32 << 30,
		ManifestFeatures:  processFeatures,
	}, lc, clk)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p.(*pool), lc
}

func level2Exec(cmd string, epoch uint64) Exec {
	return Exec{Command: cmd, TimeoutS: 30, Mode: ModeLeaseProcesses, ModeEpoch: epoch}
}

func processExec(kind ExecKind, args ProcessArgs, epoch uint64) Exec {
	e := level2Exec("", epoch)
	e.Kind, e.Process = kind, args
	return e
}

// fakeTable is a guest's tracked table as the fake VM reports it on every lease End.
type fakeTable struct {
	mu   sync.Mutex
	rows []TrackedProcess
}

func (f *fakeTable) set(rows ...TrackedProcess) {
	f.mu.Lock()
	f.rows = slices.Clone(rows)
	f.mu.Unlock()
}

func (f *fakeTable) get() []TrackedProcess {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.rows)
}

// reportTable makes every lease Run answer End with tab's rows.
func reportTable(lc *leaseLauncher, tab *fakeTable) {
	lc.setRunFn(func(_ *fakeVM, c Command, _ Sink) (Result, error) {
		return Result{Tracked: tab.get()}, nil
	})
}

func running(id, name string, pid int, started time.Time) TrackedProcess {
	return TrackedProcess{ID: id, Name: name, PID: pid, State: "running", Started: started, MemoryBytes: 4 << 20}
}

// wire is err as the client sees it.
func wire(err error) string {
	if err == nil {
		return ""
	}
	return wireError(err).Error()
}

// Review Focus 5: a process kind on a snapshot without lease-processes-v1 is refused
// lease_unsupported before anything reaches the guest -- an old agent would run it as a
// command. Nothing is restored, nothing runs, no epoch is stored.
func TestProcessKindRefusedWithoutFeature(t *testing.T) {
	p, lc, _ := leasePool(t, nil) // lease-v1 only
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	for _, k := range []ExecKind{ExecKindProcessStart, ExecKindProcessList, ExecKindProcessLogs, ExecKindProcessStop} {
		e := processExec(k, ProcessArgs{Name: "web"}, 1)
		e.Command = "python -m http.server"
		_, err := p.Exec(t.Context(), "k", e, &capturingSink{})
		if got := wire(err); !strings.HasPrefix(got, "lease_unsupported: ") || !strings.Contains(got, FeatureLeaseProcessesV1) {
			t.Fatalf("%s on a lease-v1 snapshot: err = %q, want lease_unsupported naming %s", k, got, FeatureLeaseProcessesV1)
		}
		if ReasonOf(err) != RefuseLeaseUnsupported {
			t.Fatalf("%s: ReasonOf = %q, want %q", k, ReasonOf(err), RefuseLeaseUnsupported)
		}
	}
	if n := lc.count("restore "); n != 0 {
		t.Fatalf("restores = %d, want none", n)
	}
	if n := lc.count("run "); n != 0 {
		t.Fatalf("runs = %d, want none", n)
	}
	if liveLease(p, "k") != nil {
		t.Fatal("a refused process kind started a lease")
	}

	// An unknown kind is refused the same way on any snapshot, never run as a command.
	q, lq, _ := processPool(t)
	mustSetMode(t, q, "k", ModeLeaseProcesses, 1)
	_, err := q.Exec(t.Context(), "k", processExec("process_frobnicate", ProcessArgs{}, 1), &capturingSink{})
	if got := wire(err); !strings.HasPrefix(got, "lease_unsupported: ") {
		t.Fatalf("unknown kind: err = %q, want lease_unsupported", got)
	}
	if n := lq.count("run "); n != 0 {
		t.Fatalf("unknown kind: runs = %d, want none", n)
	}
}

// A process kind below lease+processes is refused processes_not_enabled: at the Exec's own
// mode, at a served mode lowered by a same-epoch downgrade (under the gate, the lease kept),
// and with an unknown epoch (served per-exec). It never reaches the guest.
func TestProcessKindRefusedBelowLevel2(t *testing.T) {
	p, lc, _ := processPool(t)

	// No stored state: the Exec would be served per-exec.
	_, err := p.Exec(t.Context(), "k", processExec(ExecKindProcessList, ProcessArgs{}, 1), &capturingSink{})
	if got := wire(err); !strings.HasPrefix(got, "processes_not_enabled: ") {
		t.Fatalf("unknown epoch: err = %q, want processes_not_enabled", got)
	}
	if n := pinnedCount(p, "k"); n != 0 {
		t.Fatalf("pins after the refusal = %d, want 0", n)
	}

	// The Exec's own mode is lease.
	mustSetMode(t, p, "k", ModeLease, 1)
	mustExec(t, p, "k", leaseExec("one", 1))
	vm := vmID(leaseAlive(t, p, "after the level-1 Exec").vm)
	e := processExec(ExecKindProcessStart, ProcessArgs{Name: "web"}, 1)
	e.Mode = ModeLease
	_, err = p.Exec(t.Context(), "k", e, &capturingSink{})
	if got := wire(err); !strings.HasPrefix(got, "processes_not_enabled: ") {
		t.Fatalf("mode lease: err = %q, want processes_not_enabled", got)
	}
	if ReasonOf(err) != RefuseProcessesNotEnabled {
		t.Fatalf("ReasonOf = %q, want %q", ReasonOf(err), RefuseProcessesNotEnabled)
	}

	// A lease+processes token at the epoch the sandbox holds at lease: served at lease,
	// checked under the gate, and the lease is kept.
	_, err = p.Exec(t.Context(), "k", processExec(ExecKindProcessStart, ProcessArgs{Name: "web"}, 1), &capturingSink{})
	if got := wire(err); !strings.HasPrefix(got, "processes_not_enabled: ") {
		t.Fatalf("served at lease: err = %q, want processes_not_enabled", got)
	}
	if got := vmID(leaseAlive(t, p, "after the refusals").vm); got != vm {
		t.Fatalf("lease VM = %s, want %s kept", got, vm)
	}
	for _, c := range lc.commands() {
		if c.Kind != ExecKindCommand {
			t.Fatalf("a %s reached the guest", c.Kind)
		}
	}
	if n := lc.count("run "); n != 1 {
		t.Fatalf("runs = %d, want only the level-1 command", n)
	}
	if n := pinnedCount(p, "k"); n != 0 {
		t.Fatalf("pins after the refusals = %d, want 0", n)
	}
}

// No lease without a reason: process_list, process_logs and process_stop with no live lease
// answer an empty list or process_not_found without restoring a VM. process_start starts
// one, as a command does, and carries its arguments and SH_LEASE_MAX_PROCESSES.
func TestProcessListWithoutLeaseStartsNone(t *testing.T) {
	p, lc, _ := processPool(t)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)

	var out capturingSink
	res, err := p.Exec(t.Context(), "k", processExec(ExecKindProcessList, ProcessArgs{}, 1), &out)
	if err != nil || res.ExitCode != 0 || out.out() != "[]" {
		t.Fatalf("process_list: res %+v, out %q, err %v; want exit 0 and []", res, out.out(), err)
	}
	for _, tc := range []struct {
		kind ExecKind
		args ProcessArgs
		want string
	}{
		{ExecKindProcessLogs, ProcessArgs{Name: "web"}, "process_not_found: web"},
		{ExecKindProcessStop, ProcessArgs{ID: "3", Name: "web"}, "process_not_found: 3"},
		{ExecKindProcessStop, ProcessArgs{}, "process_not_found: no id or name given"},
	} {
		_, err := p.Exec(t.Context(), "k", processExec(tc.kind, tc.args, 1), &capturingSink{})
		if got := wire(err); got != tc.want {
			t.Fatalf("%s %+v: err = %q, want %q", tc.kind, tc.args, got, tc.want)
		}
	}
	if n := lc.count("restore "); n != 0 {
		t.Fatalf("restores = %d, want none", n)
	}
	if liveLease(p, "k") != nil || p.LeaseStatus("k").Pending != nil {
		t.Fatal("a process kind with no lease started one")
	}

	e := processExec(ExecKindProcessStart, ProcessArgs{Name: "web", Cwd: "app"}, 1)
	e.Command = "npm run dev"
	mustExec(t, p, "k", e)
	leaseAlive(t, p, "after process_start")
	cmds := lc.commands()
	if len(cmds) != 1 {
		t.Fatalf("Runs = %d, want 1", len(cmds))
	}
	c := cmds[0]
	if c.Kind != ExecKindProcessStart || c.Process != (ProcessArgs{Name: "web", Cwd: "app"}) ||
		c.Command != "npm run dev" || !c.Lease || c.MaxProcesses != DefaultLeaseMaxProcesses {
		t.Fatalf("process_start Command = %+v", c)
	}
}

// The mirror is refreshed from every lease End, the plain command's included, and kept in
// the state file's open lease; an End with an empty table empties it.
func TestMirrorRefreshedFromEnd(t *testing.T) {
	p, lc, clk := processPool(t)
	tab := &fakeTable{}
	reportTable(lc, tab)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)

	web := running("1", "web", 412, clk.Now())
	tab.set(web)
	mustExec(t, p, "k", processExec(ExecKindProcessStart, ProcessArgs{Name: "web"}, 1))
	if got := leaseAlive(t, p, "after the start").tracked; !slices.Equal(got, []TrackedProcess{web}) {
		t.Fatalf("mirror = %+v, want [web]", got)
	}
	if s := loadLeaseState(p.cfg.WorkspaceRoot, "k"); s.Open == nil || !trackedIDsEqual(s.Open.Tracked, "1") {
		t.Fatalf("state file open lease = %+v, want the mirror persisted", s.Open)
	}

	exited := web
	exited.State, exited.Code = "exited", 1
	job := running("2", "p2", 413, clk.Now())
	tab.set(exited, job)
	mustExec(t, p, "k", level2Exec("ls", 1)) // a plain command's End carries the table too
	if got := leaseAlive(t, p, "after the command").tracked; !slices.Equal(got, []TrackedProcess{exited, job}) {
		t.Fatalf("mirror = %+v, want [web exited, p2]", got)
	}
	if s := loadLeaseState(p.cfg.WorkspaceRoot, "k"); s.Open == nil || len(s.Open.Tracked) != 2 || s.Open.Tracked[0].State != "exited" {
		t.Fatalf("state file open lease = %+v, want the refreshed mirror", s.Open)
	}

	tab.set()
	mustExec(t, p, "k", level2Exec("ls", 1))
	if got := leaseAlive(t, p, "after the empty End").tracked; len(got) != 0 {
		t.Fatalf("mirror = %+v, want empty", got)
	}
	if s := loadLeaseState(p.cfg.WorkspaceRoot, "k"); s.Open == nil || len(s.Open.Tracked) != 0 {
		t.Fatalf("state file open lease = %+v, want an empty mirror", s.Open)
	}
}

func trackedIDsEqual(ps []TrackedProcess, ids ...string) bool {
	if len(ps) != len(ids) {
		return false
	}
	for i := range ps {
		if ps[i].ID != ids[i] {
			return false
		}
	}
	return true
}

// A lease end lists the processes running at the end, `<name> (pid <n>)` (an unnamed one
// as p<id>, ruling P5-R6) with their structured form, and the proto carries both.
func TestLeaseEndListsTrackedProcesses(t *testing.T) {
	logs := captureLog(t)
	p, lc, clk := processPool(t)
	tab := &fakeTable{}
	reportTable(lc, tab)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	started := clk.Now()
	web := running("1", "web", 412, started)
	anon := running("2", "", 413, started) // the guest names it p2; the host does too
	done := TrackedProcess{ID: "3", Name: "build", PID: 414, State: "exited", Code: 0, Started: started}
	tab.set(web, anon, done)
	mustExec(t, p, "k", level2Exec(secretCommand, 1))
	clk.Advance(90 * time.Second)

	if err := p.EndLease("k", LeaseEndReset); err != nil {
		t.Fatalf("EndLease: %v", err)
	}
	ev := p.LeaseStatus("k").Pending
	if ev == nil || ev.Reason != LeaseEndReset {
		t.Fatalf("pending = %+v, want the reset end", ev)
	}
	if want := []string{"web (pid 412)", "p2 (pid 413)"}; !slices.Equal(ev.Processes, want) {
		t.Fatalf("processes = %q, want %q", ev.Processes, want)
	}
	if !trackedIDsEqual(ev.Tracked, "1", "2") {
		t.Fatalf("tracked = %+v, want the two running processes", ev.Tracked)
	}
	// The pending event survives on disk with its lists.
	if s := loadLeaseState(p.cfg.WorkspaceRoot, "k"); s.Pending == nil || !slices.Equal(s.Pending.Processes, ev.Processes) ||
		!trackedIDsEqual(s.Pending.Tracked, "1", "2") {
		t.Fatalf("state file pending = %+v, want the lists persisted", s.Pending)
	}

	pe := leaseEventProto(ev)
	if !slices.Equal(pe.Processes, ev.Processes) || len(pe.Tracked) != 2 {
		t.Fatalf("proto = %+v, want both lists", pe)
	}
	if tp := pe.Tracked[0]; tp.Id != "1" || tp.Name != "web" || tp.Pid != 412 || tp.State != "running" ||
		tp.AgeMs != 90_000 || tp.MemoryBytes != 4<<20 {
		t.Fatalf("proto tracked[0] = %+v, want web, pid 412, running, age 90 s at the end, 4 MiB", tp)
	}
	if tp := pe.Tracked[1]; tp.Name != "p2" {
		t.Fatalf("proto tracked[1].name = %q, want p2", tp.Name)
	}

	// Spec §4.1: the end's audit record lists the tracked processes, never the command.
	line := ""
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "lease end ") {
			line = l
		}
	}
	for _, want := range []string{"reason=reset", "processes=", "1:web:running", "2:p2:running", "3:build:exited(0)"} {
		if !strings.Contains(line, want) {
			t.Fatalf("lease end audit %q lacks %q", line, want)
		}
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatal("an audit line carries the command text")
	}
}

// Review Focus 4: a worker restart while processes run. The worker_restart end lists them,
// from the mirror persisted with the open lease.
func TestWorkerRestartEndListsTrackedProcesses(t *testing.T) {
	root := t.TempDir()
	clk := newFakeClock()
	p1, lc1 := processPoolOn(t, root, clk)
	tab := &fakeTable{}
	reportTable(lc1, tab)
	mustSetMode(t, p1, "k", ModeLeaseProcesses, 1)
	started := clk.Now()
	tab.set(running("1", "web", 412, started), TrackedProcess{ID: "2", Name: "build", PID: 414, State: "exited", Started: started})
	mustExec(t, p1, "k", processExec(ExecKindProcessStart, ProcessArgs{Name: "web"}, 1))
	clk.Advance(30 * time.Second)
	if err := p1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	clk.Advance(30 * time.Second)
	p2, _ := processPoolOn(t, root, clk)
	ev := p2.LeaseStatus("k").Pending
	if ev == nil || ev.Reason != LeaseEndWorkerRestart {
		t.Fatalf("pending after the restart = %+v, want the worker_restart end", ev)
	}
	if want := []string{"web (pid 412)"}; !slices.Equal(ev.Processes, want) {
		t.Fatalf("processes = %q, want %q", ev.Processes, want)
	}
	if !trackedIDsEqual(ev.Tracked, "1") {
		t.Fatalf("tracked = %+v, want web", ev.Tracked)
	}
	if got := leaseEventProto(ev).Tracked[0].AgeMs; got != 60_000 {
		t.Fatalf("age_ms = %d, want 60 s at the restart", got)
	}
}

// LeaseStatus carries the live lease's full tracked table, exited entries with their state
// and code included (P5-R16), and the proto maps it to LeaseStatus.processes with their
// age; stopped stays empty (Task 6 fills it).
func TestLeaseStatusCarriesTracked(t *testing.T) {
	p, lc, clk := processPool(t)
	tab := &fakeTable{}
	reportTable(lc, tab)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	if got := p.LeaseStatus("k").Tracked; got != nil {
		t.Fatalf("tracked without a lease = %+v, want none", got)
	}
	started := clk.Now()
	tab.set(running("1", "web", 412, started), TrackedProcess{ID: "2", Name: "build", PID: 414, State: "exited", Code: 2, Started: started})
	mustExec(t, p, "k", processExec(ExecKindProcessStart, ProcessArgs{Name: "web"}, 1))
	clk.Advance(5 * time.Second)

	info := p.LeaseStatus("k")
	if !trackedIDsEqual(info.Tracked, "1", "2") {
		t.Fatalf("status tracked = %+v, want the full table: web and the exited build", info.Tracked)
	}
	st, err := Runner{Pool: p}.LeaseControl(context.Background(), "k", pb.LeaseOp_LEASE_OP_STATUS, 0, 0)
	if err != nil {
		t.Fatalf("LeaseControl status: %v", err)
	}
	if len(st.Processes) != 2 {
		t.Fatalf("LeaseStatus.processes = %+v, want web and build", st.Processes)
	}
	if web := st.Processes[0]; web.Name != "web" || web.Pid != 412 || web.State != "running" || web.AgeMs != 5000 {
		t.Fatalf("LeaseStatus.processes[0] = %+v, want web, pid 412, running, 5 s old", web)
	}
	if build := st.Processes[1]; build.Name != "build" || build.State != "exited" || build.Code != 2 {
		t.Fatalf("LeaseStatus.processes[1] = %+v, want build, exited, code 2", build)
	}
	if len(st.Stopped) != 0 {
		t.Fatalf("LeaseStatus.stopped = %+v, want empty", st.Stopped)
	}
}

// Spec §7's audit: one lease_process record each for start, stop and exit, with id, name,
// mode and workspace key, never the command text. An exit is found by diffing the mirror.
func TestProcessExitAudited(t *testing.T) {
	logs := captureLog(t)
	p, lc, clk := processPool(t)
	tab := &fakeTable{}
	reportTable(lc, tab)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	started := clk.Now()
	web := running("1", "web", 412, started)
	api := running("2", "api", 413, started)

	tab.set(web)
	e := processExec(ExecKindProcessStart, ProcessArgs{Name: "web"}, 1)
	e.Command = secretCommand
	mustExec(t, p, "k", e)
	tab.set(web, api)
	e.Process.Name = "api"
	mustExec(t, p, "k", e)

	webDied := web
	webDied.State, webDied.Code = "exited", 3
	tab.set(webDied, api)
	mustExec(t, p, "k", level2Exec(secretCommand, 1)) // web exits on its own: found by the diff

	apiStopped := api
	apiStopped.State, apiStopped.Code = "killed", 15
	tab.set(webDied, apiStopped)
	mustExec(t, p, "k", processExec(ExecKindProcessStop, ProcessArgs{Name: "api"}, 1))
	mustExec(t, p, "k", level2Exec("true", 1)) // nothing changes: no record

	var recs []string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "lease_process ") {
			recs = append(recs, l)
		}
	}
	want := [][]string{
		{"event=start", `workspace_key="k"`, "mode=lease+processes", "id=1", `name="web"`, "pid=412"},
		{"event=start", "id=2", `name="api"`},
		{"event=exit", "id=1", `name="web"`, "state=exited", "code=3"},
		{"event=stop", "id=2", `name="api"`, "state=killed", "code=15"},
	}
	if len(recs) != len(want) {
		t.Fatalf("lease_process records = %d, want %d:\n%s", len(recs), len(want), strings.Join(recs, "\n"))
	}
	for i, ws := range want {
		for _, w := range ws {
			if !strings.Contains(recs[i], w) {
				t.Fatalf("record %d %q lacks %q", i, recs[i], w)
			}
		}
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatal("an audit line carries the command text")
	}
}

// Task 3's carry: a guest's process refusal arrives as an error frame, and the lease is
// kept, as for the guest's own timeout. The client gets the bare wire string.
func TestGuestProcessRefusalKeepsTheLease(t *testing.T) {
	p, lc, _ := processPool(t)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	mustExec(t, p, "k", level2Exec("one", 1))
	vm := vmID(leaseAlive(t, p, "after the first Exec").vm)
	for _, msg := range []string{
		"process_not_found: web",
		"process_limit: 4 running (SH_LEASE_MAX_PROCESSES)",
		"process_name_taken: web",
		"process_cwd: /etc: outside the workspace",
		"process_signal: unknown signal FOO",
		"processes_not_enabled: no",
		"lease_unsupported: unknown kind x",
	} {
		lc.setRunFn(func(_ *fakeVM, _ Command, _ Sink) (Result, error) { return Result{}, &guestError{msg: msg} })
		_, err := p.Exec(t.Context(), "k", processExec(ExecKindProcessStop, ProcessArgs{Name: "web"}, 1), &capturingSink{})
		if got := wire(err); got != msg {
			t.Fatalf("err = %q, want the bare %q", got, msg)
		}
		if got := vmID(leaseAlive(t, p, msg).vm); got != vm {
			t.Fatalf("%s: lease VM = %s, want %s kept", msg, got, vm)
		}
	}
	// Any other guest error still ends it.
	lc.setRunFn(func(_ *fakeVM, _ Command, _ Sink) (Result, error) { return Result{}, &guestError{msg: "fork failed"} })
	if _, err := p.Exec(t.Context(), "k", level2Exec("two", 1), &capturingSink{}); !errors.Is(err, ErrGuest) {
		t.Fatalf("err = %v, want the guest error", err)
	}
	if ev := p.LeaseStatus("k").Pending; ev == nil || ev.Reason != LeaseEndAgentDead {
		t.Fatalf("pending = %+v, want agent_dead", ev)
	}
}

// Review minor 1: only a process kind's guest refusal keeps the lease. A command whose
// guest error happens to start with a refusal prefix is a genuine failure: the lease ends
// agent_dead, as for any other guest error.
func TestCommandGuestErrorWithARefusalPrefixEndsTheLease(t *testing.T) {
	p, lc, _ := processPool(t)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	mustExec(t, p, "k", level2Exec("one", 1))
	leaseAlive(t, p, "after the first Exec")
	lc.setRunFn(func(_ *fakeVM, _ Command, _ Sink) (Result, error) {
		return Result{}, &guestError{msg: "process_not_found: web"}
	})
	if _, err := p.Exec(t.Context(), "k", level2Exec("two", 1), &capturingSink{}); !errors.Is(err, ErrGuest) {
		t.Fatalf("err = %v, want the guest error", err)
	}
	if l := liveLease(p, "k"); l != nil {
		t.Fatal("the lease survived a command's guest error")
	}
	if ev := p.LeaseStatus("k").Pending; ev == nil || ev.Reason != LeaseEndAgentDead {
		t.Fatalf("pending = %+v, want agent_dead", ev)
	}
}

// Review minor 2: a process kind served per-exec by a same-epoch downgrade while a lease
// is live (routeExec's endFirst case, which pins the run). The refusal releases that pin
// and ends nothing: the lease stays until the downgrade's own SetMode ends it
// (mode_change) after the Exec in flight.
func TestProcessKindRefusedOnASameEpochDowngradeWithALiveLease(t *testing.T) {
	p, lc, _ := processPool(t)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	entered, release := blockRuns(lc)
	first := execAsync(p, "k", level2Exec("one", 1))
	recvWithin(t, entered, "the first Exec's Run")
	vm := vmID(leaseAlive(t, p, "during the first Exec").vm)
	setMode := make(chan error, 1)
	go func() { setMode <- p.SetMode("k", ModePerExec, 1) }() // stored at once, then waits for the gate
	waitFor(t, func() bool { return pinnedCount(p, "k") == 2 })

	_, err := p.Exec(t.Context(), "k", processExec(ExecKindProcessList, ProcessArgs{}, 1), &capturingSink{})
	if got := wire(err); !strings.HasPrefix(got, "processes_not_enabled: ") || !strings.Contains(got, "per-exec") {
		t.Fatalf("err = %q, want processes_not_enabled at per-exec", got)
	}
	if n := pinnedCount(p, "k"); n != 2 {
		t.Fatalf("pins after the refusal = %d, want 2: its own pin released", n)
	}
	if got := vmID(leaseAlive(t, p, "after the refusal").vm); got != vm {
		t.Fatalf("lease VM = %s, want %s: the refusal ended nothing", got, vm)
	}
	if ev := p.LeaseStatus("k").Pending; ev != nil && ev.State == leaseEventEnd {
		t.Fatalf("pending = %+v: the refusal ended the lease", ev)
	}

	close(release)
	for _, errc := range []<-chan error{first, setMode} {
		if err := recvWithin(t, errc, "the first Exec or the SetMode"); err != nil {
			t.Fatalf("%v", err)
		}
	}
	if n := pinnedCount(p, "k"); n != 0 {
		t.Fatalf("pins at the end = %d, want 0", n)
	}
	if ev := p.LeaseStatus("k").Pending; ev == nil || ev.Reason != LeaseEndModeChange {
		t.Fatalf("pending = %+v, want the downgrade's mode_change", ev)
	}
	for _, c := range lc.commands() {
		if c.Kind != ExecKindCommand {
			t.Fatalf("a %s reached the guest", c.Kind)
		}
	}
	if n := lc.count("run "); n != 1 {
		t.Fatalf("runs = %d, want only the first command", n)
	}
}

// process_stop may take ~20 s in the guest (TERM, 10 s, cgroup.kill, the teardown bound),
// so a process kind's host budget is at least ProcessKindMinTimeoutS whatever it asked for.
func TestProcessKindTimeoutFloor(t *testing.T) {
	p, lc, clk := processPool(t)
	mustSetMode(t, p, "k", ModeLeaseProcesses, 1)
	mustExec(t, p, "k", level2Exec("one", 1))
	entered, release := blockRuns(lc)
	e := processExec(ExecKindProcessStop, ProcessArgs{Name: "web"}, 1)
	e.TimeoutS = 1
	errc := execAsync(p, "k", e)
	<-entered
	clk.Advance(20 * time.Second)
	select {
	case err := <-errc:
		t.Fatalf("process_stop with timeout_s=1 ended at 20 s: %v", err)
	default:
	}
	close(release)
	if err := <-errc; err != nil {
		t.Fatalf("process_stop: %v", err)
	}
	if c := lc.commands(); c[len(c)-1].TimeoutS < ProcessKindMinTimeoutS {
		t.Fatalf("guest timeout_s = %d, want at least %d", c[len(c)-1].TimeoutS, ProcessKindMinTimeoutS)
	}
}
