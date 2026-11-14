package vmpool

import (
	"fmt"
	"log"
	"strings"
	"time"

	ga "github.com/rossoctl/moca/remote-worker/internal/guestagent"
)

// The host-side tracked mirror of a level-2 lease (plan 5): the tracked-process entry, the
// mirror's refresh from every lease End, its lease_process audit records, and the lease
// end's audit field.

// TrackedProcess is one entry of a lease guest's tracked-process table (plan 5), as the
// guest's End reports it (guestagent.TrackedProcess). State is running, exited or killed;
// Code is the exit code, or the signal number when killed. Started is the guest's clock,
// which every lease request sets from the host's (Request.HostUnixNanos).
type TrackedProcess struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	PID         int       `json:"pid"`
	State       string    `json:"state"`
	Code        int       `json:"code,omitempty"`
	Started     time.Time `json:"started"`
	MemoryBytes int64     `json:"memory_bytes,omitempty"`
}

// DisplayName is how the process is shown: its name, or p<id> when it has none (ruling
// P5-R6). The guest already reports an unnamed process as p<id>; this is the same rule.
func (tp TrackedProcess) DisplayName() string {
	if tp.Name == "" {
		return "p" + tp.ID
	}
	return tp.Name
}

// Display is the process as clients render it: "<name> (pid <n>)".
func (tp TrackedProcess) Display() string {
	return fmt.Sprintf("%s (pid %d)", tp.DisplayName(), tp.PID)
}

// stateText is the process's state as process_list spells it (spec §7): running,
// exited(<code>) or killed(<signal>).
func (tp TrackedProcess) stateText() string {
	if tp.State == ga.TrackedRunning {
		return tp.State
	}
	return fmt.Sprintf("%s(%d)", tp.State, tp.Code)
}

func (tp TrackedProcess) running() bool { return tp.State == ga.TrackedRunning }

// runningTracked is the running entries of ps, nil when there are none.
func runningTracked(ps []TrackedProcess) []TrackedProcess {
	var out []TrackedProcess
	for _, tp := range ps {
		if tp.running() {
			out = append(out, tp)
		}
	}
	return out
}

// displays is each process's Display, nil for none.
func displays(ps []TrackedProcess) []string {
	var out []string
	for _, tp := range ps {
		out = append(out, tp.Display())
	}
	return out
}

// refreshTrackedLocked replaces l's tracked mirror with next, the table a lease End of
// Exec e reported (plan 5): every lease End carries the whole table, so the mirror is
// never stale, and an End without one (an empty table, or a level-1 agent) empties it. It
// writes a lease_process record for each start, stop and exit the change shows
// (auditTracked), and saves the mirror with the open lease when one did, so a
// worker_restart end lists what was running (endLeasesOpenAtStart). A change in memory
// alone is not saved: the file is fsynced under p.mu, and a worker_restart end has no use
// for a footprint. Caller holds p.mu and rp's gate, with l live.
func (p *pool) refreshTrackedLocked(rp *runPool, l *vmLease, e Exec, next []TrackedProcess) {
	prev := l.tracked
	l.tracked = next
	if !auditTracked(rp.key, l.mode, e, prev, next) {
		return
	}
	s := p.leaseStateLocked(rp)
	if s.Open == nil {
		return
	}
	o := *s.Open // copied, not written through: the cached state may share it
	o.Tracked = next
	s.Open = &o
	if err := saveLeaseState(p.cfg.WorkspaceRoot, rp.key, s); err != nil {
		// The open record only lets a worker_restart end list the processes: losing it
		// loses that list, not safety (startLease's trade).
		log.Printf("vmpool: lease tracked processes for %q: %v", rp.key, err)
	}
	rp.state = s
}

// auditTracked writes the lease_process records (spec §7) for the change from prev to next,
// the mirror before and after Exec e's End, and reports whether the table changed in
// anything but memory. A new entry is a start; an entry that left running is an exit, or
// the stop when e is the process_stop that named it, which is recorded even when the
// process had already exited (the stop still signals what its cgroup holds). A running
// entry that vanished is an exit with state gone (the guest never drops a running one).
// Each record carries the id, name, mode and workspace key, never the command text.
func auditTracked(key string, mode Mode, e Exec, prev, next []TrackedProcess) bool {
	rec := func(event string, tp TrackedProcess, state string) {
		log.Printf("vmpool: lease_process event=%s workspace_key=%q mode=%s id=%s name=%q pid=%d state=%s code=%d",
			event, key, mode, tp.ID, tp.DisplayName(), tp.PID, state, tp.Code)
	}
	stopped := -1
	if e.Kind == ExecKindProcessStop {
		stopped = findTracked(next, e.Process)
	}
	old := make(map[string]TrackedProcess, len(prev))
	for _, tp := range prev {
		old[tp.ID] = tp
	}
	changed := len(prev) != len(next)
	for i, tp := range next {
		was, ok := old[tp.ID]
		delete(old, tp.ID)
		if !ok {
			changed = true
			rec("start", tp, tp.State)
		} else {
			was.MemoryBytes, was.Started = tp.MemoryBytes, tp.Started
			changed = changed || was != tp
		}
		switch {
		case i == stopped:
			// Accepted (review minor 3): a guest that answers the stop before the process
			// dies leaves it running here, and a later End then writes its exit as well.
			rec("stop", tp, tp.State)
		case !tp.running() && (!ok || was.running()):
			rec("exit", tp, tp.State)
		}
	}
	for _, tp := range prev {
		if _, gone := old[tp.ID]; gone {
			changed = true
			if tp.running() {
				rec("exit", tp, "gone")
			}
		}
	}
	return changed
}

// findTracked is the index in ps of the entry args names, as the guest finds it: by id when
// one is given, else by name, an id winning over an equal name (ruling P5-R6); -1 if none.
func findTracked(ps []TrackedProcess, args ProcessArgs) int {
	key := args.ID
	if key == "" {
		key = args.Name
	}
	if key == "" {
		return -1
	}
	for i, tp := range ps {
		if tp.ID == key {
			return i
		}
	}
	for i, tp := range ps {
		if tp.DisplayName() == key {
			return i
		}
	}
	return -1
}

// trackedAuditField is a lease end's audit field for its tracked processes (spec §4.1:
// id, name and exit state), " processes=[<id>:<name>:<state> ...]", or "" for none.
func trackedAuditField(ps []TrackedProcess) string {
	if len(ps) == 0 {
		return ""
	}
	parts := make([]string, len(ps))
	for i, tp := range ps {
		parts[i] = tp.ID + ":" + tp.DisplayName() + ":" + tp.stateText()
	}
	return " processes=[" + strings.Join(parts, " ") + "]"
}
