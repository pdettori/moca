//go:build linux

package guestagent

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The exec identity the lease tests drop to (global constraints: uid and gid 7000).
const testExecID = "7000"

// requireRootCgroupV2 skips a lease test unless it runs as root on a cgroup v2 host:
// the shim's privilege drop, and the cgroup work of the later lease tasks, need both.
// CI runs these in the microvm-gates job under sudo; `make test` skips them.
func requireRootCgroupV2(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root and cgroup v2")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("needs root and cgroup v2")
	}
}

// runInShim runs argv through the test binary acting as the lease shim, as the exec
// identity, and returns its combined output. The working directory is / because the
// package directory need not be traversable by uid 7000.
func runInShim(t *testing.T, home string, argv ...string) string {
	t.Helper()
	args := append([]string{ShimArg, testExecID, testExecID, home, "sbx", "--"}, argv...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim %v: %v\n%s", argv, err, out)
	}
	return string(out)
}

func TestShimDropsToTheExecUserWithNoPrivileges(t *testing.T) {
	requireRootCgroupV2(t)
	home := t.TempDir()
	out := runInShim(t, home, "bash", "-c",
		`echo "uid=$(id -u)"; echo "gid=$(id -g)"; echo "groups=$(id -G)"; echo "home=$HOME"; echo "user=$USER"; echo "logname=$LOGNAME"; `+
			`grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' /proc/self/status`)

	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.Contains(k, ":") {
			got[k] = v
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			got[k] = strings.TrimSpace(v)
		}
	}
	want := map[string]string{
		"uid":        testExecID,
		"gid":        testExecID,
		"groups":     testExecID,
		"home":       home,
		"user":       "sbx",
		"logname":    "sbx",
		"CapInh":     "0000000000000000",
		"CapPrm":     "0000000000000000",
		"CapEff":     "0000000000000000",
		"CapBnd":     "0000000000000000",
		"CapAmb":     "0000000000000000",
		"NoNewPrivs": "1",
		"Seccomp":    "2",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q\nfull output:\n%s", k, got[k], v, out)
		}
	}
}

// The shim must clear the inheritable set itself, not rely on the agent starting with
// it empty: CapInh survives setresuid and execve. AmbientCaps makes Go raise
// CAP_NET_BIND_SERVICE in the shim's permitted, inheritable and ambient sets before it
// execs the test binary, and root's execve keeps the inheritable set.
func TestShimClearsAnInheritedCapabilitySet(t *testing.T) {
	requireRootCgroupV2(t)
	args := []string{ShimArg, testExecID, testExecID, t.TempDir(), "sbx", "--",
		"grep", "-E", "^(CapInh|CapAmb):", "/proc/self/status"}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_BIND_SERVICE}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim: %v\n%s", err, out)
	}
	for _, want := range []string{"CapInh:\t0000000000000000", "CapAmb:\t0000000000000000"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// The setup above must actually hand the shim a non-empty inheritable set, or the
	// assertion is vacuous: the same launch without the shim shows it.
	probe := exec.Command("grep", "^CapInh:", "/proc/self/status")
	probe.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_BIND_SERVICE}}
	pout, err := probe.CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, pout)
	}
	if strings.Contains(string(pout), "0000000000000000") {
		t.Fatalf("AmbientCaps did not raise CapInh, so this test proves nothing: %s", pout)
	}
}

// Every call targets the caller itself, which an unfiltered process may do: TRACEME
// needs no tracer privilege and reading one's own memory passes the ptrace access
// check. So EPERM here is the filter's doing, not the uid drop's.
const ptraceAndProcessVMScript = `
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
r = libc.ptrace(0, 0, None, None)
print("ptrace", r, ctypes.get_errno() if r == -1 else 0)
src = ctypes.create_string_buffer(b"lease", 8)
dst = ctypes.create_string_buffer(8)
local = iovec(ctypes.cast(dst, ctypes.c_void_p), 8)
remote = iovec(ctypes.cast(src, ctypes.c_void_p), 8)
libc.process_vm_readv.restype = ctypes.c_ssize_t
ctypes.set_errno(0)
r = libc.process_vm_readv(os.getpid(), ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
print("process_vm_readv", r, ctypes.get_errno() if r == -1 else 0)
libc.process_vm_writev.restype = ctypes.c_ssize_t
ctypes.set_errno(0)
r = libc.process_vm_writev(os.getpid(), ctypes.byref(remote), 1, ctypes.byref(local), 1, 0)
print("process_vm_writev", r, ctypes.get_errno() if r == -1 else 0)
libc.syscall.restype = ctypes.c_long
pidfd = libc.syscall(434, os.getpid(), 0)  # pidfd_open (434 on amd64 and arm64)
ctypes.set_errno(0)
r = libc.syscall(438, pidfd, 0, 0)  # pidfd_getfd(pidfd, fd 0, 0)
print("pidfd_getfd", r, ctypes.get_errno() if r == -1 else 0)
`

func TestShimSeccompDeniesPtraceAndProcessVM(t *testing.T) {
	requireRootCgroupV2(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3")
	}
	out := runInShim(t, t.TempDir(), "python3", "-c", ptraceAndProcessVMScript)
	for _, want := range []string{"ptrace -1 1", "process_vm_readv -1 1", "process_vm_writev -1 1", "pidfd_getfd -1 1"} { // errno 1 = EPERM
		if !strings.Contains(out, want+"\n") {
			t.Errorf("output lacks %q (want EPERM):\n%s", want, out)
		}
	}
}

// The agent runs at oom_score_adj -1000 once it serves leases, and a fork inherits
// that. An Exec must stay an OOM candidate, or an OOM finds nothing it may kill: the
// shim puts it back to 0, and the exec uid cannot lower it again. sh stands in for the
// agent here: it lowers its own, then execs the shim, which inherits it.
func TestShimResetsTheInheritedOomScoreAdj(t *testing.T) {
	requireRootCgroupV2(t)
	cmd := exec.Command("sh", "-c",
		`echo -1000 > /proc/self/oom_score_adj && echo "pre=$(cat /proc/self/oom_score_adj)" && exec "$0" "$@"`,
		os.Args[0], ShimArg, testExecID, testExecID, t.TempDir(), "sbx", "--",
		"sh", "-c", `cat /proc/self/oom_score_adj; { echo -1000 > /proc/self/oom_score_adj; } 2>/dev/null; echo rc=$?`)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim: %v\n%s", err, out)
	}
	if want := "pre=-1000\n0\nrc=1\n"; string(out) != want {
		t.Errorf("output %q, want %q", out, want)
	}
}

// The agent ignores TERM, INT and HUP (cmd/guest-agent), and an ignored disposition
// survives fork and execve. The shim must hand the command default dispositions, or
// process_stop's TERM (and an Exec's own kill -INT or timeout -s HUP) would do nothing.
// sh stands in for the agent: it ignores them, then execs the shim, which inherits that.
func TestShimResetsInheritedIgnoredSignals(t *testing.T) {
	requireRootCgroupV2(t)
	cmd := exec.Command("sh", "-c", `trap '' HUP INT TERM PIPE USR1; exec "$0" "$@"`,
		os.Args[0], ShimArg, testExecID, testExecID, t.TempDir(), "sbx", "--",
		"grep", "-E", "^Sig(Ign|Blk):", "/proc/self/status")
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim: %v\n%s", err, out)
	}
	if want := "SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n"; string(out) != want {
		t.Errorf("the command's signal state:\n%s\nwant nothing blocked or ignored", out)
	}
}

func TestShimSetuidBinaryDoesNotRegainRoot(t *testing.T) {
	requireRootCgroupV2(t)
	dir := t.TempDir()
	if mountIsNosuid(t, dir) {
		t.Skipf("%s is on a nosuid mount, so a setuid bit proves nothing there", dir)
	}
	// t.TempDir and its parent are 0700 root; uid 7000 must traverse them to exec.
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id := filepath.Join(dir, "id")
	copyFile(t, "/usr/bin/id", id)
	if err := os.Chown(id, 0, 0); err != nil {
		t.Fatal(err)
	}
	// After the chown: chown clears the setuid bit.
	if err := os.Chmod(id, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(id); err != nil || fi.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("%s is not setuid: %v %v", id, fi.Mode(), err)
	}
	// id -u prints the effective uid, which a honoured setuid bit would make 0.
	if out := strings.TrimSpace(runInShim(t, t.TempDir(), id, "-u")); out != testExecID {
		t.Errorf("setuid-root id -u printed euid %q, want %s", out, testExecID)
	}
}

func TestSeccompFilterRefusesUnknownArch(t *testing.T) {
	if _, err := seccompFilter("mips"); err == nil {
		t.Error("seccompFilter(\"mips\") returned no error")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if p, err := seccompFilter(arch); err != nil || len(p) == 0 {
			t.Errorf("seccompFilter(%q) = %d instructions, %v", arch, len(p), err)
		}
	}
}

// seccompFilter spells the denied syscall numbers out per arch, because x/sys only
// defines SYS_* for the arch it is built for. This pins those literals to x/sys for the
// arch under test, so a typo cannot quietly allow ptrace.
func TestSeccompFilterDeniesTheBuildArchSyscalls(t *testing.T) {
	prog, err := seccompFilter(runtime.GOARCH)
	if err != nil {
		t.Skipf("no filter for %s: %v", runtime.GOARCH, err)
	}
	compared := map[uint32]bool{}
	for _, ins := range prog {
		if ins.Code == unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K {
			compared[ins.K] = true
		}
	}
	for name, nr := range map[string]uint32{
		"ptrace":            unix.SYS_PTRACE,
		"process_vm_readv":  unix.SYS_PROCESS_VM_READV,
		"process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
		"pidfd_getfd":       unix.SYS_PIDFD_GETFD,
	} {
		if !compared[nr] {
			t.Errorf("filter for %s never compares nr with %s (%d)", runtime.GOARCH, name, nr)
		}
	}
}

func TestShimArgsRejectAnEmptyHomeOrCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"empty home", []string{"7000", "7000", "", "sbx", "--", "true"}},
		{"empty user", []string{"7000", "7000", "/tmp/sbx-home", "", "--", "true"}},
		{"no user", []string{"7000", "7000", "/tmp/sbx-home", "--", "true"}},
		{"empty argv[0]", []string{"7000", "7000", "/tmp/sbx-home", "sbx", "--", ""}},
		{"no argv", []string{"7000", "7000", "/tmp/sbx-home", "sbx", "--"}},
		{"root uid", []string{"0", "7000", "/tmp/sbx-home", "sbx", "--", "true"}},
		{"no separator", []string{"7000", "7000", "/tmp/sbx-home", "sbx", "true", "x"}},
	} {
		if _, err := parseShimArgs(tc.args); err == nil {
			t.Errorf("%s: parseShimArgs(%q) accepted it", tc.name, tc.args)
		}
	}
	got, err := parseShimArgs([]string{"20001", "7000", "/tmp/sbx-proc-20001", "sbxp1", "--", "true", "x"})
	if err != nil {
		t.Errorf("valid args rejected: %v", err)
	}
	if got.uid != 20001 || got.gid != 7000 || got.home != "/tmp/sbx-proc-20001" || got.user != "sbxp1" || !slices.Equal(got.argv, []string{"true", "x"}) {
		t.Errorf("parseShimArgs = %+v", got)
	}
	// The same check must be what the shim process does: step "args", exit 127.
	cmd := exec.Command(os.Args[0], ShimArg, "7000", "7000", "", "sbx", "--", "true")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 127 || !strings.Contains(string(out), "guest-agent: lease-shim: args: ") {
		t.Errorf("shim with an empty home: err %v, output %q; want exit 127 at step args", err, out)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// mountIsNosuid reports whether path's mount (the longest mount point that prefixes
// it in /proc/self/mountinfo) carries the nosuid per-mount option.
func mountIsNosuid(t *testing.T, path string) bool {
	t.Helper()
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	best, nosuid := "", false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Fields: id parent major:minor root mountpoint options ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		mp := fields[4]
		if mp != "/" && path != mp && !strings.HasPrefix(path, mp+"/") {
			continue
		}
		if len(mp) >= len(best) {
			best = mp
			nosuid = false
			for _, o := range strings.Split(fields[5], ",") {
				if o == "nosuid" {
					nosuid = true
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return nosuid
}

// newLeaseAgent starts an Agent in lease mode on a per-test cgroup root,
// /sys/fs/cgroup/moca-ga-test-<random>, which t.Cleanup removes after the agent is
// closed. It returns the agent and that root. The workspace is a tmpfs of its own,
// as /workspace is a mount in a guest: the first lease request remounts it nodev,nosuid.
// The user-namespace sysctl that request writes is a scratch file here, so the suite
// does not change the test host (TestLeaseFirstRequestDisablesUserNamespaces checks the
// real one). The workspace and HOME are made traversable, because t.TempDir and its
// parent are 0700 root and the Exec runs as 7000.
func newLeaseAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	return newLeaseAgentWith(t, nil)
}

// newLeaseAgentWith is newLeaseAgent with the lease options adjusted by opt (nil: none).
// The tracked processes' homes go under a scratch parent, not the test host's /tmp.
func newLeaseAgentWith(t *testing.T, opt func(*LeaseOptions)) (*Agent, string) {
	t.Helper()
	requireRootCgroupV2(t)
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	root := "/sys/fs/cgroup/moca-ga-test-" + hex.EncodeToString(b[:])
	t.Cleanup(func() { removeCgroupTree(t, root) })

	sysctl := filepath.Join(t.TempDir(), "max_user_namespaces")
	if err := os.WriteFile(sysctl, []byte("15000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	origSysctl := userNamespacesSysctl
	userNamespacesSysctl = sysctl
	t.Cleanup(func() { userNamespacesSysctl = origSysctl })

	// The first lease request lowers the agent's oom_score_adj; here the agent is the
	// test binary, which must stay an OOM candidate like any other process.
	oomAdj := filepath.Join(t.TempDir(), "oom_score_adj")
	if err := os.WriteFile(oomAdj, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	origOomAdj := agentOomScoreAdjPath
	agentOomScoreAdjPath = oomAdj
	t.Cleanup(func() { agentOomScoreAdjPath = origOomAdj })

	work := t.TempDir()
	homeParent := t.TempDir()
	if err := unix.Mount("tmpfs", work, "tmpfs", 0, "size=4m,mode=0755"); err != nil {
		t.Fatalf("mount tmpfs workspace: %v", err)
	}
	// Registered before the agent's Close, so it runs after it (cleanups are LIFO).
	t.Cleanup(func() {
		if err := unix.Unmount(work, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount workspace %s: %v", work, err)
		}
	})
	for _, d := range []string{filepath.Dir(work), work, homeParent} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	trackedHomes := t.TempDir()
	if err := os.Chmod(trackedHomes, 0o755); err != nil {
		t.Fatal(err)
	}
	origHomes := trackedHomeParent
	trackedHomeParent = trackedHomes
	t.Cleanup(func() { trackedHomeParent = origHomes })
	id, _ := strconv.Atoi(testExecID)
	lo := LeaseOptions{CgroupRoot: root, UID: id, GID: id, Home: filepath.Join(homeParent, "home"), ShimPath: os.Args[0]}
	if opt != nil {
		opt(&lo)
	}
	a, err := NewAgent(AgentOptions{WorkDir: work, ScratchDir: t.TempDir(), Lease: lo})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, root
}

// removeCgroupTree removes root's per-Exec and tracked cgroups, then root. A cgroup left
// by a failed teardown, or a tracked process still running, may take a moment to empty
// after its cgroup.kill, so it retries.
func removeCgroupTree(t *testing.T, root string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		subs, _ := filepath.Glob(filepath.Join(root, "e*"))
		tracked, _ := filepath.Glob(filepath.Join(root, "tracked", "p[0-9]*"))
		for _, s := range append(append(subs, tracked...), filepath.Join(root, "tracked")) {
			_ = os.WriteFile(filepath.Join(s, "cgroup.kill"), []byte("1"), 0)
			_ = os.Remove(s)
		}
		err := os.Remove(root)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("removing test cgroup %s: %v", root, err)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func leaseReq(cmd string) Request { return Request{Command: cmd, Lease: true, CapBytes: 1 << 20} }

// procsMatching lists the live processes whose space-joined cmdline matches re and,
// if uid >= 0, whose real uid is uid. A zombie has an empty cmdline, so it never matches.
func procsMatching(t *testing.T, re *regexp.Regexp, uid int) []string {
	t.Helper()
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(d, "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		cmd := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		if !re.MatchString(cmd) {
			continue
		}
		if uid >= 0 && procUID(d) != uid {
			continue
		}
		out = append(out, filepath.Base(d)+": "+cmd)
	}
	return out
}

func procUID(procDir string) int {
	st, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(st), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "Uid:" {
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return -1
}

func TestLeaseKillsEveryProcessTheExecStarted(t *testing.T) {
	a, root := newLeaseAgent(t)
	out, stderr, end, errMsg := drive(t, a, leaseReq(
		`sleep 300 & setsid sleep 301 & nohup sleep 302 >/dev/null 2>&1 & (sleep 303 &); ( setsid bash -c 'sleep 304 &' ); echo started`), nil)
	if errMsg != "" || end.ExitCode != 0 || out != "started\n" {
		t.Fatalf("end %+v, err %q, stdout %q, stderr %q", end, errMsg, out, stderr)
	}
	// Checked at once, not polled: the cgroup must be empty BEFORE End goes out.
	if left := procsMatching(t, regexp.MustCompile(`^sleep 30[0-4]$`), -1); len(left) > 0 {
		t.Errorf("processes the Exec started survived its End: %v", left)
	}
	if _, err := os.Stat(filepath.Join(root, "e1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s/e1 still exists after End (stat err %v)", root, err)
	}
}

func TestLeaseEndDoesNotWaitForABackgroundPipeHolder(t *testing.T) {
	a, _ := newLeaseAgent(t)
	start := time.Now()
	out, _, end, errMsg := drive(t, a, leaseReq(`sleep 300 & echo hi`), nil)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("End took %s: it waited on the background job holding stdout", el)
	}
	if errMsg != "" || end.ExitCode != 0 || out != "hi\n" {
		t.Fatalf("end %+v, err %q, stdout %q", end, errMsg, out)
	}
}

// setChildSubreaperForTheRestOfTheBinary makes the test process a child subreaper, so
// an Exec's orphans reparent to it as they would to the agent as PID 1 in a guest.
// It cannot safely be unset (orphans already reparented would be left to whoever
// clears it), so it stays set for the rest of the test binary's life. Later tests are
// unaffected: os/exec waits on its own children by pidfd, and orphans of later tests
// become at worst zombies of this short-lived process.
func setChildSubreaperForTheRestOfTheBinary(t *testing.T) {
	t.Helper()
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatalf("PR_SET_CHILD_SUBREAPER: %v", err)
	}
}

// zombieChildren lists this process's children in state Z.
func zombieChildren(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	var out []string
	for _, d := range dirs {
		st, err := os.ReadFile(filepath.Join(d, "stat"))
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...; comm may contain spaces and parentheses.
		i := strings.LastIndexByte(string(st), ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(st[i+1:]))
		if len(f) < 2 || f[0] != "Z" {
			continue
		}
		if ppid, _ := strconv.Atoi(f[1]); ppid == self {
			out = append(out, string(st[:i+1]))
		}
	}
	return out
}

func TestLeaseReapsOrphansAndKeepsTheExitCode(t *testing.T) {
	requireRootCgroupV2(t)
	setChildSubreaperForTheRestOfTheBinary(t)
	a, _ := newLeaseAgent(t)
	for i := range 20 {
		_, stderr, end, errMsg := drive(t, a, leaseReq(`for i in 1 2 3; do sleep 100 & done; exit 7`), nil)
		if errMsg != "" || end.ExitCode != 7 {
			t.Fatalf("request %d: end %+v, err %q, stderr %q; want exit 7", i, end, errMsg, stderr)
		}
	}
	// The cgroup empties before the last orphans finish reparenting (cgroup_exit runs
	// before exit_notify), so their SIGCHLD can land just after End: allow the reaper
	// that moment, but no more.
	deadline := time.Now().Add(2 * time.Second)
	for {
		z := zombieChildren(t)
		if len(z) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d unreaped zombie children of the test process: %v", len(z), z)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLeaseRunsEachExecInAFreshShell(t *testing.T) {
	a, _ := newLeaseAgent(t)
	if _, stderr, end, errMsg := drive(t, a, leaseReq(`export FOO=1; cd /; alias x=y; f(){ :; }`), nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("request 1: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	out, stderr, end, errMsg := drive(t, a, leaseReq(`echo "${FOO-unset}"; pwd; type f >/dev/null 2>&1 && echo has-f || echo no-f`), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("request 2: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	if want := "unset\n" + a.WorkDir() + "\nno-f\n"; out != want {
		t.Errorf("request 2 stdout %q, want %q: state leaked from request 1", out, want)
	}
}

func TestLeaseExecCannotLeaveOrTouchTheCgroupTree(t *testing.T) {
	a, root := newLeaseAgent(t)
	out, stderr, end, errMsg := drive(t, a, leaseReq(fmt.Sprintf(
		`echo $$ > %[1]s/cgroup.procs 2>/dev/null; echo procs=$?; mkdir %[1]s/evil 2>/dev/null; echo mkdir=$?; kill -STOP %[2]d 2>/dev/null; echo kill=$?`,
		root, os.Getpid())), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	for _, step := range []string{"procs", "mkdir", "kill"} {
		m := regexp.MustCompile(`(?m)^` + step + `=(\d+)$`).FindStringSubmatch(out)
		if m == nil || m[1] == "0" {
			t.Errorf("%s: exit status %v, want non-zero\n%s", step, m, out)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "evil")); err == nil {
		t.Errorf("the Exec created %s/evil", root)
	}

	out, stderr, end, errMsg = drive(t, a, leaseReq(fmt.Sprintf(`echo $$; echo ---; cat %[1]s/e2/cgroup.procs; echo ---; cat %[1]s/cgroup.procs`, root)), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("second Exec: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	parts := strings.Split(out, "---\n")
	if len(parts) != 3 {
		t.Fatalf("second Exec output %q", out)
	}
	pid := strings.TrimSpace(parts[0])
	if !slicesContainsLine(parts[1], pid) {
		t.Errorf("pid %s is not in %s/e2/cgroup.procs (%q)", pid, root, parts[1])
	}
	if slicesContainsLine(parts[2], pid) {
		t.Errorf("pid %s is in %s/cgroup.procs, the root", pid, root)
	}
}

func slicesContainsLine(text, line string) bool {
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

func TestLeaseTimeoutKillsTheCgroupAndKeepsTheAgent(t *testing.T) {
	a, _ := newLeaseAgent(t)
	req := leaseReq(`sleep 30 & sleep 30`)
	req.TimeoutS = 1
	if _, _, _, errMsg := drive(t, a, req, nil); errMsg != "timeout:1" {
		t.Fatalf("error %q, want timeout:1", errMsg)
	}
	// uid 7000 only: earlier parked-shell timeout tests in this binary leave root-owned
	// `sleep 30`s running for half a minute, and they are not this Exec's.
	if left := procsMatching(t, regexp.MustCompile(`^sleep 30$`), 7000); len(left) > 0 {
		t.Errorf("the timed-out Exec's processes survived: %v", left)
	}
	if out, _, end, errMsg := drive(t, a, leaseReq(`echo ok`), nil); errMsg != "" || end.ExitCode != 0 || out != "ok\n" {
		t.Fatalf("lease request after a timeout: end %+v, err %q, stdout %q", end, errMsg, out)
	}
}

func TestLeaseTeardownFailureMarksTheAgentDead(t *testing.T) {
	a, _ := newLeaseAgent(t)
	orig := waitCgroupEmpty
	waitCgroupEmpty = func(*execCgroup, time.Duration) error { return errors.New("injected: still populated") }
	t.Cleanup(func() { waitCgroupEmpty = orig })

	_, _, end, errMsg := drive(t, a, leaseReq(`echo hi; exit 3`), nil)
	if errMsg != "" || !end.TeardownFailed || end.ExitCode != 3 {
		t.Fatalf("end %+v, err %q; want teardown_failed with the command's exit 3", end, errMsg)
	}
	if _, _, _, errMsg := drive(t, a, leaseReq(`true`), nil); !strings.Contains(errMsg, "teardown failed") {
		t.Fatalf("next request's error %q, want it to say teardown failed", errMsg)
	}
}

func TestLeaseStdinWritesAFileAsTheExecUser(t *testing.T) {
	a, _ := newLeaseAgent(t)
	id, _ := strconv.Atoi(testExecID)
	if err := os.Chown(a.WorkDir(), id, id); err != nil {
		t.Fatal(err)
	}
	req := leaseReq(`base64 -d > f`)
	req.HasStdin = true
	if _, stderr, end, errMsg := drive(t, a, req, []byte("aGk=")); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	path := filepath.Join(a.WorkDir(), "f")
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "hi" {
		t.Fatalf("f = %q, %v; want hi", got, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != id || int(st.Gid) != id {
		t.Errorf("f owned by %d:%d, want %d:%d", st.Uid, st.Gid, id, id)
	}
}

func TestLeaseLatchRefusesPerExecAfterTheFirstLease(t *testing.T) {
	a, _ := newLeaseAgent(t)
	if _, _, end, errMsg := drive(t, a, leaseReq(`true`), nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("lease true: end %+v, err %q", end, errMsg)
	}
	_, _, _, errMsg := drive(t, a, Request{Command: "true", CapBytes: 1 << 20}, nil)
	if want := "guest-agent: this agent serves lease requests only"; errMsg != want {
		t.Fatalf("per-Exec request after a lease: error %q, want %q", errMsg, want)
	}
}

func TestLeaseLatchIsNotSetByPerExecRequests(t *testing.T) {
	a, _ := newLeaseAgent(t)
	pid := a.ShellPID()
	for i := range 2 {
		if _, _, end, errMsg := drive(t, a, Request{Command: "true", CapBytes: 1 << 20}, nil); errMsg != "" || end.ExitCode != 0 {
			t.Fatalf("per-Exec request %d: end %+v, err %q", i, end, errMsg)
		}
	}
	if a.leaseOn.Load() {
		t.Error("a per-Exec request set the lease latch")
	}
	if a.lease.r.Load() != nil {
		t.Error("a per-Exec request started the reaper")
	}
	if a.ShellPID() != pid {
		t.Errorf("ShellPID changed %d -> %d", pid, a.ShellPID())
	}
}

// The workspace newLeaseAgent makes is root-owned and 0755, so `touch` as 7000 fails
// unless normalisation ran first, and before the Exec.
func TestLeaseNormaliseWorkspaceHandsTheWorkspaceToTheExecUser(t *testing.T) {
	a, _ := newLeaseAgent(t)
	req := leaseReq(`touch f`)
	req.NormaliseWorkspace = true
	if _, stderr, end, errMsg := drive(t, a, req, nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	id, _ := strconv.Atoi(testExecID)
	for _, p := range []string{a.WorkDir(), filepath.Join(a.WorkDir(), "f")} {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		if int(st.Uid) != id || int(st.Gid) != id {
			t.Errorf("%s owned by %d:%d, want %d:%d", p, st.Uid, st.Gid, id, id)
		}
	}
}

// Not root-only: the first request's remount fails on the missing workspace before any
// cgroup or shim work, so the agent need not have been prepared for lease mode.
func TestLeaseFirstRequestRemountFailureDoesNotSetTheLatch(t *testing.T) {
	a := newTestAgent(t)
	a.opts.Lease.CgroupRoot = "/nonexistent/moca-ga-test"
	a.opts.WorkDir = filepath.Join(t.TempDir(), "missing")
	req := leaseReq(`true`)
	req.NormaliseWorkspace = true
	_, _, _, errMsg := drive(t, a, req, nil)
	if want := "guest-agent: lease: remount workspace nodev,nosuid: " + a.opts.WorkDir + ": "; !strings.HasPrefix(errMsg, want) {
		t.Fatalf("error %q, want it to start %q", errMsg, want)
	}
	if a.leaseOn.Load() {
		t.Error("a failed lease request set the lease latch")
	}
}

// A workspace mounted read-only lets the first request's remount and sysctl write
// through, then fails the normalise walk's first chown with EROFS. The latch must stay
// unset, and once the workspace is writable again the next request runs.
func TestLeaseNormaliseWorkspaceFailureDoesNotSetTheLatch(t *testing.T) {
	a, _ := newLeaseAgent(t)
	ws := a.WorkDir()
	if err := unix.Mount("", ws, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		t.Fatalf("remount ro: %v", err)
	}
	req := leaseReq(`true`)
	req.NormaliseWorkspace = true
	_, _, _, errMsg := drive(t, a, req, nil)
	if want := "normalise workspace: " + ws + ": "; !strings.HasPrefix(errMsg, want) {
		t.Fatalf("error %q, want it to start %q", errMsg, want)
	}
	if a.leaseOn.Load() {
		t.Error("a failed normalisation set the lease latch")
	}
	if err := unix.Mount("", ws, "", unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
		t.Fatalf("remount rw: %v", err)
	}
	if _, stderr, end, errMsg := drive(t, a, req, nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("retry: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	if !a.leaseOn.Load() {
		t.Error("the successful retry did not set the lease latch")
	}
}

// mountOptions returns the per-mount options of the mount at exactly mountPoint, from
// /proc/self/mountinfo (field 6), or fails the test if there is none.
func mountOptions(t *testing.T, mountPoint string) []string {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var opts []string
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) >= 6 && f[4] == mountPoint {
			opts = strings.Split(f[5], ",") // the last match is the top of the stack
		}
	}
	if opts == nil {
		t.Fatalf("no mount at %s in /proc/self/mountinfo", mountPoint)
	}
	return opts
}

// Spec §3.3, no route back to root: a device node in the workspace (root left it, or
// a per-Exec run made it) is removed before the Exec uid is handed the tree, and the
// workspace is remounted nodev,nosuid with its other options kept.
func TestLeaseFirstRequestRemovesDevicesAndRemountsNoDevNoSuid(t *testing.T) {
	a, _ := newLeaseAgent(t)
	ws := a.WorkDir()
	if err := unix.Mount("", ws, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_NOATIME, ""); err != nil {
		t.Fatalf("remount noatime: %v", err)
	}
	null := filepath.Join(ws, "null")
	if err := unix.Mknod(null, unix.S_IFCHR|0o666, int(unix.Mkdev(1, 3))); err != nil {
		t.Fatalf("mknod c 1 3: %v", err)
	}
	blk := filepath.Join(ws, "sub", "blk")
	if err := os.Mkdir(filepath.Dir(blk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(blk, unix.S_IFBLK|0o600, int(unix.Mkdev(7, 0))); err != nil {
		t.Fatalf("mknod b 7 0: %v", err)
	}
	req := leaseReq(`true`)
	req.NormaliseWorkspace = true
	if _, stderr, end, errMsg := drive(t, a, req, nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	for _, p := range []string{null, blk} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived normalisation (lstat err %v)", p, err)
		}
	}
	opts := mountOptions(t, ws)
	for _, want := range []string{"rw", "nodev", "nosuid", "noatime"} {
		if !slices.Contains(opts, want) {
			t.Errorf("workspace mount options %v lack %s", opts, want)
		}
	}
}

// The real sysctl, unlike the rest of the suite: the first lease request writes 0 to
// it, a per-Exec request does not. The test host's value is put back afterwards.
func TestLeaseFirstRequestDisablesUserNamespaces(t *testing.T) {
	a, _ := newLeaseAgent(t)
	userNamespacesSysctl = "/proc/sys/user/max_user_namespaces"
	orig, err := os.ReadFile(userNamespacesSysctl)
	if err != nil {
		t.Skipf("no user namespace sysctl: %v", err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile("/proc/sys/user/max_user_namespaces", orig, 0); err != nil {
			t.Errorf("restoring max_user_namespaces to %q: %v", strings.TrimSpace(string(orig)), err)
		}
	})
	if strings.TrimSpace(string(orig)) == "0" {
		if err := os.WriteFile(userNamespacesSysctl, []byte("15000"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, end, errMsg := drive(t, a, Request{Command: "true", CapBytes: 1 << 20}, nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("per-Exec request: end %+v, err %q", end, errMsg)
	}
	if got, _ := os.ReadFile(userNamespacesSysctl); strings.TrimSpace(string(got)) == "0" {
		t.Fatal("a per-Exec request disabled user namespaces")
	}
	if _, _, end, errMsg := drive(t, a, leaseReq(`true`), nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("lease request: end %+v, err %q", end, errMsg)
	}
	if got, _ := os.ReadFile(userNamespacesSysctl); strings.TrimSpace(string(got)) != "0" {
		t.Errorf("max_user_namespaces is %q after the first lease request, want 0", strings.TrimSpace(string(got)))
	}
	if out, _, _, errMsg := drive(t, a, leaseReq(`unshare -U true 2>/dev/null; echo rc=$?`), nil); errMsg != "" || out == "rc=0\n" {
		t.Errorf("unshare -U in a lease Exec: %q, err %q; want it refused", out, errMsg)
	}
}

// Spec §3.3: every Exec runs with umask 0002. Inside the normalised workspace, whose
// root is setgid, a new directory inherits setgid, so mkdir gives 2775, not 775.
func TestLeaseExecUmaskIs0002(t *testing.T) {
	a, _ := newLeaseAgent(t)
	req := leaseReq(`umask; touch f; mkdir d; stat -c %a f d`)
	req.NormaliseWorkspace = true
	out, stderr, end, errMsg := drive(t, a, req, nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	if want := "0002\n664\n2775\n"; out != want {
		t.Errorf("stdout %q, want %q", out, want)
	}
}

// fd hygiene: the agent's listener, the request connection, the cgroup dir fd and the
// Exec's own pipe ends must not reach an Exec. Only 0, 1 and 2 (and bash's own 255, if
// it opens one) may be open in it. The open listener comes from listenSocket, the
// vsock listener's creation path (AF_UNIX, as the test host may lack vsock): Listen's
// unix: scheme goes through net.Listen, which is close-on-exec regardless.
func TestLeaseExecInheritsOnlyStdio(t *testing.T) {
	a, _ := newLeaseAgent(t)
	lfd, err := listenSocket(unix.AF_UNIX)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(lfd) })
	if err := unix.Bind(lfd, &unix.SockaddrUnix{Name: filepath.Join(t.TempDir(), "agent.sock")}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(lfd, 8); err != nil {
		t.Fatal(err)
	}
	// The shell lists its own fds, not ls's (a pipeline element's $BASHPID is its own
	// pid), and into a file: while a pipe or a $(...) runs, the shell holds its end.
	out, stderr, end, errMsg := drive(t, a, leaseReq(`p=$BASHPID; ls /proc/$p/fd >"$HOME/fdl"; sort -n "$HOME/fdl" | tr '\n' ' '`), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	if got := strings.TrimSpace(out); got != "0 1 2" && got != "0 1 2 255" {
		t.Errorf("fds open in the Exec: %q, want 0 1 2 (and maybe 255)", got)
	}
}

// listenSocket is listenVsock's socket creation; AF_UNIX stands in for AF_VSOCK, which
// the test host may lack. Not root-only.
func TestListenSocketIsCloseOnExec(t *testing.T) {
	fd, err := listenSocket(unix.AF_UNIX)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("the listening socket lacks FD_CLOEXEC: every lease Exec would inherit the agent's listener")
	}
}

// statOwner returns path's owner and mode bits without following a symlink.
func statOwner(t *testing.T, path string) (uid, gid int, mode uint32) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return int(st.Uid), int(st.Gid), st.Mode & 0o7777
}

func TestNormaliseWorkspaceOwnsGroupWritesAndStaysInside(t *testing.T) {
	requireRootCgroupV2(t)
	ws, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(ws, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "d", "b"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(ws, "ln")); err != nil {
		t.Fatal(err)
	}
	m := filepath.Join(ws, "m")
	if err := os.Mkdir(m, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", m, "tmpfs", 0, "size=1m,mode=0755"); err != nil {
		t.Fatalf("mount tmpfs: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(m, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount %s: %v", m, err)
		}
	})
	if err := os.WriteFile(filepath.Join(m, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// The umask must not decide the starting modes the assertions below build on.
	for p, mode := range map[string]os.FileMode{ws: 0o755, filepath.Join(ws, "a"): 0o644, filepath.Join(ws, "d"): 0o755, filepath.Join(ws, "d", "b"): 0o644} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := normaliseWorkspace(ws, 7000, 7000); err != nil {
		t.Fatalf("normaliseWorkspace: %v", err)
	}

	for rel, wantMode := range map[string]uint32{".": 0o2775, "a": 0o664, "d": 0o2775, "d/b": 0o664} {
		uid, gid, mode := statOwner(t, filepath.Join(ws, rel))
		if uid != 7000 || gid != 7000 {
			t.Errorf("%s owned by %d:%d, want 7000:7000", rel, uid, gid)
		}
		if mode != wantMode {
			t.Errorf("%s mode %04o, want %04o", rel, mode, wantMode)
		}
	}
	if uid, gid, _ := statOwner(t, filepath.Join(ws, "ln")); uid != 7000 || gid != 7000 {
		t.Errorf("ln owned by %d:%d, want 7000:7000", uid, gid)
	}
	if uid, gid, mode := statOwner(t, target); uid != 0 || gid != 0 || mode != 0o644 {
		t.Errorf("symlink target is %d:%d %04o, want 0:0 0644: the walk followed ln", uid, gid, mode)
	}
	for _, p := range []string{m, filepath.Join(m, "x")} {
		if uid, gid, _ := statOwner(t, p); uid != 0 || gid != 0 {
			t.Errorf("%s owned by %d:%d, want 0:0: the walk crossed the mount", p, uid, gid)
		}
	}
}

// A timeout and a failed teardown together must still reach the host as
// teardown_failed: a KindError would be an opaque guest error to vmpool (spec §3.1).
func TestLeaseTimeoutWithTeardownFailureStillReportsTeardownFailed(t *testing.T) {
	a, _ := newLeaseAgent(t)
	orig := waitCgroupEmpty
	waitCgroupEmpty = func(*execCgroup, time.Duration) error { return errors.New("injected: still populated") }
	t.Cleanup(func() { waitCgroupEmpty = orig })

	req := leaseReq(`sleep 30`)
	req.TimeoutS = 1
	_, _, end, errMsg := drive(t, a, req, nil)
	if errMsg != "" || !end.TeardownFailed || end.ExitCode != -1 {
		t.Fatalf("end %+v, err %q; want an End with teardown_failed and exit -1", end, errMsg)
	}
	if _, _, _, errMsg := drive(t, a, leaseReq(`true`), nil); !strings.Contains(errMsg, "teardown failed") {
		t.Fatalf("next request's error %q, want it to say teardown failed", errMsg)
	}
}

// The host aborts an Exec by closing the connection (vmpool's closeConn on ctx.Done).
// The cgroup must be killed then, as on a timeout, and the agent must take the next Exec.
func TestLeaseConnectionCloseKillsTheExec(t *testing.T) {
	a, _ := newLeaseAgent(t)
	host, guest := net.Pipe()
	served := make(chan struct{})
	go func() { _ = a.ServeConn(guest); close(served) }()
	if err := WriteJSON(host, KindRequest, leaseReq(`sleep 30 & sleep 30`)); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(host, KindStdinEOF, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	sleeps := regexp.MustCompile(`^sleep 30$`)
	if n := len(procsMatching(t, sleeps, 7000)); n != 2 {
		t.Fatalf("%d `sleep 30`s running as 7000 before the close, want 2: the test would prove nothing", n)
	}
	_ = host.Close()

	deadline := time.Now().Add(6 * time.Second)
	for len(procsMatching(t, sleeps, 7000)) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the aborted Exec's processes survived 6 s: %v", procsMatching(t, sleeps, 7000))
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-served:
	case <-time.After(6 * time.Second):
		t.Fatal("ServeConn did not return after the host closed the connection")
	}
	if out, _, end, errMsg := drive(t, a, leaseReq(`echo ok`), nil); errMsg != "" || end.ExitCode != 0 || out != "ok\n" {
		t.Fatalf("lease request after an abort: end %+v, err %q, stdout %q", end, errMsg, out)
	}
}

// Close must not wait for a running lease Exec: it once took the lease mutex, which
// runLease holds for the Exec's whole run.
func TestLeaseCloseDoesNotWaitForARunningExec(t *testing.T) {
	a, _ := newLeaseAgent(t)
	req := leaseReq(`sleep 30`)
	req.TimeoutS = 3 // ends the Exec on its own once the reaper is stopped
	done := make(chan struct{})
	go func() { defer close(done); _, _, _, _ = drive(t, a, req, nil) }()
	t.Cleanup(func() { <-done })
	sleeps := regexp.MustCompile(`^sleep 30$`)
	for deadline := time.Now().Add(2 * time.Second); len(procsMatching(t, sleeps, 7000)) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the Exec never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { _ = a.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on the running lease Exec")
	}
}

// fakeMemInfo points memInfoPath at a meminfo whose MemTotal is memTotal bytes, for
// the rest of the test.
func fakeMemInfo(t *testing.T, memTotal int64) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "meminfo")
	body := fmt.Sprintf("MemTotal:       %d kB\nMemFree:        1024 kB\n", memTotal>>10)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := memInfoPath
	memInfoPath = p
	t.Cleanup(func() { memInfoPath = orig })
}

// subtreeControllers is the controllers dir enables for its children.
func subtreeControllers(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(raw))
}

// Plan 1 review (#706): an OOM or a fork bomb in one Exec must cost that Exec, not the
// guest. The first lease request enables pids and memory for the cgroup root's
// children (and so in its parent first), and each e<seq> is capped. The Exec reads its
// own cgroup's caps, which proves it runs in the capped cgroup.
func TestLeasePrepareEnablesPidsAndMemory(t *testing.T) {
	a, root := newLeaseAgent(t)
	fakeMemInfo(t, 1024<<20)
	if got := subtreeControllers(t, root); len(got) != 0 {
		t.Fatalf("%s enables %v before any lease request, want nothing", root, got)
	}
	out, stderr, end, errMsg := drive(t, a, leaseReq(`c=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); cat "$c/memory.max" "$c/pids.max"`), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	if want := "939524096\n4096\n"; out != want {
		t.Errorf("the Exec's memory.max and pids.max: %q, want %q", out, want)
	}
	for _, dir := range []string{filepath.Dir(root), root} {
		got := subtreeControllers(t, dir)
		for _, c := range []string{"pids", "memory"} {
			if !slices.Contains(got, c) {
				t.Errorf("%s/cgroup.subtree_control is %v, lacks %s", dir, got, c)
			}
		}
	}
}

// PR #763 review (F1): memory.max on each e<seq> alone lets tmpfs pages escape it. A
// page an Exec writes to /tmp or /var outlives the Exec, and once its cgroup is removed
// the charge moves to the cgroup root, so the next e<seq> would start from zero over it
// and the guest would OOM globally. The first lease request caps the root as well, with
// the same values: the limit is hierarchical and counts the reparented charge.
func TestLeasePrepareCapsTheCgroupRoot(t *testing.T) {
	a, root := newLeaseAgent(t)
	fakeMemInfo(t, 1024<<20)
	if _, stderr, end, errMsg := drive(t, a, leaseReq(`true`), nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	for file, want := range map[string]string{"memory.max": "939524096", "pids.max": "4096"} {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(raw)); got != want {
			t.Errorf("%s/%s = %q, want %q", root, file, got, want)
		}
	}
}

// Refuse lease service rather than serve an Exec uncapped. A process in the cgroup
// root makes enabling memory for its children fail (EBUSY, no internal processes): the
// request fails, the latch stays unset, and once the root is empty the next request
// enables the controllers and runs.
func TestLeaseControllersFailureRefusesTheLease(t *testing.T) {
	a, root := newLeaseAgent(t)
	sleeper := exec.Command("sleep", "60")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	kill := func() {
		if !killed {
			killed = true
			_ = sleeper.Process.Kill()
			_ = sleeper.Wait()
		}
	}
	t.Cleanup(kill) // before removeCgroupTree, which cannot remove a populated root
	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte(strconv.Itoa(sleeper.Process.Pid)), 0); err != nil {
		t.Fatalf("moving sleep into %s: %v", root, err)
	}
	_, _, _, errMsg := drive(t, a, leaseReq(`true`), nil)
	if want := "guest-agent: lease: enable pids and memory in " + root + ": "; !strings.HasPrefix(errMsg, want) {
		t.Fatalf("error %q, want it to start %q", errMsg, want)
	}
	if a.leaseOn.Load() {
		t.Error("a request refused for want of cgroup caps set the lease latch")
	}
	if subs, _ := filepath.Glob(filepath.Join(root, "e*")); len(subs) != 0 {
		t.Errorf("a refused request left %v", subs)
	}
	kill()
	if _, stderr, end, errMsg := drive(t, a, leaseReq(`true`), nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("retry: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	if !a.leaseOn.Load() {
		t.Error("the successful retry did not set the lease latch")
	}
}

// Without a MemTotal there is no memory.max to give an Exec, so it is refused and its
// cgroup removed, rather than run uncapped.
func TestLeaseExecWithoutAMemTotalIsRefused(t *testing.T) {
	a, root := newLeaseAgent(t)
	orig := memInfoPath
	memInfoPath = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { memInfoPath = orig })
	_, _, _, errMsg := drive(t, a, leaseReq(`true`), nil)
	if want := "guest-agent: lease: cgroup caps: "; !strings.HasPrefix(errMsg, want) {
		t.Fatalf("error %q, want it to start %q", errMsg, want)
	}
	if subs, _ := filepath.Glob(filepath.Join(root, "e*")); len(subs) != 0 {
		t.Errorf("a refused Exec left %v", subs)
	}
}

// The first lease request, and no per-Exec request, lowers the agent's oom_score_adj
// (newLeaseAgent points it at a scratch file).
func TestLeaseFirstRequestSetsTheAgentOomScoreAdj(t *testing.T) {
	a, _ := newLeaseAgent(t)
	if _, _, end, errMsg := drive(t, a, Request{Command: "true", CapBytes: 1 << 20}, nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("per-Exec request: end %+v, err %q", end, errMsg)
	}
	if got, _ := os.ReadFile(agentOomScoreAdjPath); strings.TrimSpace(string(got)) != "0" {
		t.Fatalf("oom_score_adj %q after a per-Exec request, want 0", got)
	}
	if _, _, end, errMsg := drive(t, a, leaseReq(`true`), nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("lease request: end %+v, err %q", end, errMsg)
	}
	if got, _ := os.ReadFile(agentOomScoreAdjPath); strings.TrimSpace(string(got)) != "-1000" {
		t.Errorf("oom_score_adj %q after the first lease request, want -1000", got)
	}
}

// Not root-only. protectAgentFromOOM writes -1000; a failure is logged, never fatal.
func TestAgentOomScoreAdj(t *testing.T) {
	orig := agentOomScoreAdjPath
	t.Cleanup(func() { agentOomScoreAdjPath = orig })
	var logs strings.Builder
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	agentOomScoreAdjPath = filepath.Join(t.TempDir(), "oom_score_adj")
	if err := os.WriteFile(agentOomScoreAdjPath, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	protectAgentFromOOM()
	if got, _ := os.ReadFile(agentOomScoreAdjPath); string(got) != "-1000" {
		t.Errorf("oom_score_adj %q, want -1000", got)
	}
	if logs.Len() != 0 {
		t.Errorf("a successful write logged %q", logs.String())
	}

	agentOomScoreAdjPath = filepath.Join(t.TempDir(), "missing", "oom_score_adj")
	protectAgentFromOOM()
	if want := "guest-agent: lease: oom_score_adj -1000: "; !strings.Contains(logs.String(), want) {
		t.Errorf("a failed write logged %q, want it to contain %q", logs.String(), want)
	}
}

// PR #763 second review (G3): the cgroupfs reads behind the lease OOM hint, on a fake
// cgroup tree (no root needed): the Exec cgroup's memory.events oom_kill, read before it
// is removed, then the root's memory.current against its memory.max.
func TestLeaseMemoryHintReadsTheCgroupFiles(t *testing.T) {
	root := t.TempDir()
	e := filepath.Join(root, "e1")
	if err := os.Mkdir(e, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(e, "memory.events"), "low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\noom_group_kill 0\n")
	if n := (&execCgroup{path: e}).oomKills(); n != 1 {
		t.Fatalf("oomKills = %d, want 1", n)
	}
	if n := (&execCgroup{path: filepath.Join(root, "e2")}).oomKills(); n != 0 {
		t.Fatalf("oomKills of a cgroup with no memory.events = %d, want 0", n)
	}

	write(filepath.Join(root, "memory.current"), "314572800\n")
	write(filepath.Join(root, "memory.max"), "419430400\n")
	if got := leaseMemoryHintFor(root, 1); !strings.Contains(got, "300 MiB is still held in the lease") {
		t.Fatalf("hint = %q, want one naming the 300 MiB the lease holds", got)
	}
	if got := leaseMemoryHintFor(root, 0); got != "" {
		t.Fatalf("hint with no OOM kill = %q, want none", got)
	}
	write(filepath.Join(root, "memory.max"), "max\n")
	if got := leaseMemoryHintFor(root, 1); got != "" {
		t.Fatalf("hint with an uncapped root = %q, want none", got)
	}
	if got := leaseMemoryHintFor(filepath.Join(root, "missing"), 1); got != "" {
		t.Fatalf("hint with unreadable root files = %q, want none", got)
	}
}

func TestShimEnvSetsTheGivenUser(t *testing.T) {
	got := shimEnv([]string{"PATH=/bin", "HOME=/root", "USER=root", "LOGNAME=root", "USERX=kept"}, "/tmp/sbx-proc-20001", "sbxp1")
	want := []string{"PATH=/bin", "USERX=kept", "HOME=/tmp/sbx-proc-20001", "USER=sbxp1", "LOGNAME=sbxp1"}
	if !slices.Equal(got, want) {
		t.Fatalf("shimEnv = %q, want %q", got, want)
	}
}

// waitStatusExit is the wait status of a process that exited with code.
func waitStatusExit(code int) syscall.WaitStatus { return syscall.WaitStatus(code << 8) }

// runLease calls cancel after every Exec and expect before every fork; a tracked
// process outlives both, so its registration must too. It fires once.
func TestReaperTrackedRegistrationSurvivesCancelAndExpect(t *testing.T) {
	r := newReaper()
	var got []int
	r.track(100, func(ws syscall.WaitStatus) { got = append(got, ws.ExitStatus()) })
	r.cancel()
	r.expect()
	r.cancel()
	r.deliver(100, waitStatusExit(7))
	r.deliver(100, waitStatusExit(8)) // a recycled pid, untracked now: an orphan
	if !slices.Equal(got, []int{7}) {
		t.Fatalf("onExit calls = %v, want one, with code 7", got)
	}
}

// A tracked process can exit between its fork and track: its status is then in early,
// and track hands it over at once. track closes the registration window, as await does.
func TestReaperTrackHandsOverAnEarlyExit(t *testing.T) {
	r := newReaper()
	r.expect()
	r.deliver(100, waitStatusExit(5))
	var got []int
	r.track(100, func(ws syscall.WaitStatus) { got = append(got, ws.ExitStatus()) })
	if !slices.Equal(got, []int{5}) {
		t.Fatalf("onExit calls = %v, want one, with code 5", got)
	}
	if r.pending || len(r.early) != 0 || len(r.tracked) != 0 {
		t.Fatalf("after track: pending %v, early %v, tracked %d; want the window closed and nothing held", r.pending, r.early, len(r.tracked))
	}
}

// onExit runs without the reaper's lock, so it may call back into the reaper.
func TestReaperOnExitRunsOutsideTheLock(t *testing.T) {
	r := newReaper()
	done := make(chan struct{})
	r.track(100, func(syscall.WaitStatus) { r.cancel(); close(done) })
	go r.deliver(100, waitStatusExit(0))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("onExit deadlocked against the reaper's lock")
	}
}

// The same with a real child and the real reaper loop: registered with track, the
// child's exit reaches onExit although cancel and expect ran while it lived.
func TestReaperTrackedChildIsReapedAfterCancel(t *testing.T) {
	r := startReaper()
	t.Cleanup(r.stop)
	r.expect()
	pid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-c", "sleep 0.3; exit 7"}, &syscall.ProcAttr{})
	if err != nil {
		r.cancel()
		t.Fatal(err)
	}
	got := make(chan syscall.WaitStatus, 1)
	r.track(pid, func(ws syscall.WaitStatus) { got <- ws })
	r.cancel()
	r.expect()
	r.cancel()
	select {
	case ws := <-got:
		if !ws.Exited() || ws.ExitStatus() != 7 {
			t.Fatalf("status %v, want exit 7", ws)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the tracked child's exit never reached onExit")
	}
}

// The tracked range must be real and must not hold the exec uid: a tracked process
// sharing the Exec's uid could be traced by any later Exec (spec §3.3). Checked before
// leasePrepare touches anything, so no root is needed.
func TestLeasePrepareRejectsABadTrackedUIDRange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		base, max int
	}{
		{"negative base", -1, 4},
		{"negative count", 20000, -1},
		{"holds the exec uid", 6998, 4},
		{"starts at the exec uid", 7000, 1},
	} {
		_, err := NewAgent(AgentOptions{WorkDir: t.TempDir(), ScratchDir: t.TempDir(), Lease: LeaseOptions{
			CgroupRoot: filepath.Join(t.TempDir(), "never-made"), UID: 7000, GID: 7000, Home: filepath.Join(t.TempDir(), "home"),
			TrackedUIDBase: tc.base, MaxTrackedUIDs: tc.max,
		}})
		if err == nil || !strings.Contains(err.Error(), "tracked uids") {
			t.Errorf("%s: NewAgent err = %v, want a tracked uids refusal", tc.name, err)
		}
	}
}

func TestLeaseTrackedUIDDefaults(t *testing.T) {
	if DefaultTrackedUIDBase != 20000 || DefaultMaxTrackedUIDs != 4 {
		t.Fatalf("defaults %d, %d; want 20000 and 4 (global constraints)", DefaultTrackedUIDBase, DefaultMaxTrackedUIDs)
	}
	a, _ := newLeaseAgent(t)
	if lo := a.opts.Lease; lo.TrackedUIDBase != 20000 || lo.MaxTrackedUIDs != 4 {
		t.Fatalf("lease options %+v, want the tracked defaults filled in", lo)
	}
	if a.lease.uids == nil || a.lease.uids.base != 20000 || a.lease.uids.n != 4 {
		t.Fatalf("uid allocator %+v, want 20000 and 4", a.lease.uids)
	}
}

// ---- Level 2: tracked processes (process_start, list, logs, stop, stop_all) ----

// The tracked uids of the default range (global constraints).
const (
	trackedUID0 = 20000
	trackedUID1 = 20001
)

func procReq(kind string, args ProcessArgs) Request {
	return Request{Lease: true, Kind: kind, Process: &args, CapBytes: 1 << 20}
}

// startedProcess is process_start's stdout.
type startedProcess struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	PID  int    `json:"pid"`
}

// startProc runs process_start and returns its result; maxProcs 0 sends none.
func startProc(t *testing.T, a *Agent, name, cmd string, maxProcs int) startedProcess {
	t.Helper()
	p, errMsg := tryStartProc(t, a, ProcessArgs{Name: name}, cmd, maxProcs)
	if errMsg != "" {
		t.Fatalf("process_start %q (%s): %s", name, cmd, errMsg)
	}
	return p
}

func tryStartProc(t *testing.T, a *Agent, args ProcessArgs, cmd string, maxProcs int) (startedProcess, string) {
	t.Helper()
	req := procReq(RequestKindProcessStart, args)
	req.Command, req.MaxProcesses = cmd, maxProcs
	out, stderr, end, errMsg := drive(t, a, req, nil)
	if errMsg != "" {
		return startedProcess{}, errMsg
	}
	var p startedProcess
	if err := json.Unmarshal([]byte(out), &p); err != nil || p.ID == "" || p.PID <= 0 {
		t.Fatalf("process_start stdout %q (stderr %q): %v; want {id,name,pid}", out, stderr, err)
	}
	if !slices.ContainsFunc(end.Tracked, func(tp TrackedProcess) bool { return tp.ID == p.ID }) {
		t.Fatalf("process_start End.Tracked %+v lacks the new process %s", end.Tracked, p.ID)
	}
	return p, ""
}

func listProcs(t *testing.T, a *Agent) []TrackedProcess {
	t.Helper()
	out, stderr, end, errMsg := drive(t, a, procReq(RequestKindProcessList, ProcessArgs{}), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("process_list: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	var ps []TrackedProcess
	if err := json.Unmarshal([]byte(out), &ps); err != nil || ps == nil {
		t.Fatalf("process_list stdout %q: %v; want a JSON array", out, err)
	}
	return ps
}

func procByID(ps []TrackedProcess, id string) (TrackedProcess, bool) {
	for _, p := range ps {
		if p.ID == id {
			return p, true
		}
	}
	return TrackedProcess{}, false
}

// waitProcExit polls process_list until id is no longer running.
func waitProcExit(t *testing.T, a *Agent, id string) TrackedProcess {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p, ok := procByID(listProcs(t, a), id)
		if !ok {
			t.Fatalf("process %s is not in process_list", id)
		}
		if p.State != TrackedRunning {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %s still running after 10s", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func procLogs(t *testing.T, a *Agent, args ProcessArgs) (string, string) {
	t.Helper()
	out, _, _, errMsg := drive(t, a, procReq(RequestKindProcessLogs, args), nil)
	return out, errMsg
}

// waitLog polls process_logs until the process's log contains want.
func waitLog(t *testing.T, a *Agent, id, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, errMsg := procLogs(t, a, ProcessArgs{ID: id, Tail: 10000})
		if errMsg != "" {
			t.Fatalf("process_logs %s: %s", id, errMsg)
		}
		if strings.Contains(out, want) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %s log never showed %q; it is %q", id, want, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stopProc(t *testing.T, a *Agent, args ProcessArgs) TrackedProcess {
	t.Helper()
	out, stderr, end, errMsg := drive(t, a, procReq(RequestKindProcessStop, args), nil)
	if errMsg != "" || end.TeardownFailed {
		t.Fatalf("process_stop %+v: end %+v, err %q, stderr %q", args, end, errMsg, stderr)
	}
	var p TrackedProcess
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("process_stop stdout %q: %v", out, err)
	}
	return p
}

// pidAlive reports whether pid is a live process (not gone, not a zombie).
func pidAlive(pid int) bool {
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(st), ')')
	return i >= 0 && !strings.HasPrefix(strings.TrimSpace(string(st[i+1:])), "Z")
}

// waitPidsGone waits until none of pids is alive.
func waitPidsGone(t *testing.T, what string, pids ...int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var alive []int
		for _, p := range pids {
			if pidAlive(p) {
				alive = append(alive, p)
			}
		}
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: pids %v still alive", what, alive)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pidsOf returns the pids of procsMatching's results.
func pidsOf(t *testing.T, re *regexp.Regexp, uid int) []int {
	t.Helper()
	var out []int
	for _, p := range procsMatching(t, re, uid) {
		n, _ := strconv.Atoi(strings.SplitN(p, ":", 2)[0])
		out = append(out, n)
	}
	return out
}

// waitPidOf polls until exactly one live process matches re under uid, and returns it.
func waitPidOf(t *testing.T, re *regexp.Regexp, uid int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ps := pidsOf(t, re, uid); len(ps) == 1 {
			return ps[0]
		} else if time.Now().After(deadline) {
			t.Fatalf("processes matching %s as uid %d: %v, want exactly one", re, uid, ps)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func cgroupProcs(t *testing.T, dir string) []int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		t.Fatalf("read %s/cgroup.procs: %v", dir, err)
	}
	var out []int
	for _, f := range strings.Fields(string(raw)) {
		n, _ := strconv.Atoi(f)
		out = append(out, n)
	}
	return out
}

// A tracked process runs under its own uid, the sbx-ws group, its own HOME (0700, its
// own), in tracked/p<id> with the Exec caps, in its own session, stdin /dev/null,
// umask 0002, and with stdout and stderr in its ring.
func TestProcessStartRunsUnderItsOwnUIDAndCgroup(t *testing.T) {
	a, root := newLeaseAgent(t)
	p := startProc(t, a, "probe", `echo "uid=$(id -u) gid=$(id -g) groups=$(id -G)"; echo "home=$HOME user=$USER"; `+
		`echo "umask=$(umask)"; echo "stdin=$(readlink /proc/self/fd/0)"; echo "pid=$$ sid=$(cut -d' ' -f6 /proc/$$/stat)"; `+
		`echo "cg=$(cat /proc/self/cgroup)"; grep -E '^Sig(Ign|Blk):' /proc/self/status; `+
		`p=$BASHPID; ls /proc/$p/fd >"$HOME/fdl"; echo "fds=$(sort -n "$HOME/fdl" | tr '\n' ' ')"; `+
		`echo to-stderr >&2; echo ready; exec sleep 3001`, 0)
	if p.Name != "probe" {
		t.Errorf("name %q, want probe", p.Name)
	}
	logs := waitLog(t, a, p.ID, "ready")
	home := filepath.Join(trackedHomeParent, "sbx-proc-20000")
	for _, want := range []string{
		"uid=20000 gid=7000 groups=7000\n", "home=" + home + " user=sbxp0\n", "umask=0002\n", "stdin=/dev/null\n",
		fmt.Sprintf("pid=%d sid=%d\n", p.PID, p.PID), "cg=0::/" + filepath.Base(root) + "/tracked/p" + p.ID + "\n", "to-stderr\n",
		"SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n", "fds=0 1 2 \n",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
	if uid, gid, mode := statOwner(t, home); uid != trackedUID0 || gid != 7000 || mode&0o7777 != 0o700 {
		t.Errorf("home %s: %d:%d %o, want 20000:7000 0700", home, uid, gid, mode&0o7777)
	}
	cg := filepath.Join(root, "tracked", "p"+p.ID)
	memMax, err := execMemoryMax()
	if err != nil {
		t.Fatal(err)
	}
	// The kernel rounds memory.max down to a page.
	page := int64(os.Getpagesize())
	for f, want := range map[string]string{"memory.max": strconv.FormatInt(memMax/page*page, 10), "pids.max": strconv.Itoa(execCgroupPidsMax)} {
		if got, err := os.ReadFile(filepath.Join(cg, f)); err != nil || strings.TrimSpace(string(got)) != want {
			t.Errorf("%s/%s = %q, %v; want %s", cg, f, got, err, want)
		}
	}
	if uid, gid, _ := statOwner(t, cg); uid != 0 || gid != 0 {
		t.Errorf("%s owned by %d:%d, want root: the tracked tree is not delegated", cg, uid, gid)
	}
	ps := listProcs(t, a)
	if len(ps) != 1 || ps[0].ID != p.ID || ps[0].Name != "probe" || ps[0].PID != p.PID || ps[0].State != TrackedRunning ||
		ps[0].MemoryBytes <= 0 || ps[0].StartedUnixMs <= 0 {
		t.Errorf("process_list %+v, want one running probe with its pid and memory", ps)
	}
	stopProc(t, a, ProcessArgs{Name: "probe"})
}

// Spec §3.1: the end-of-Exec kill touches only e<seq>; a tracked process outlives every
// later Exec, and every lease End, a command's included, carries the table.
func TestTrackedSurvivesExecKill(t *testing.T) {
	a, root := newLeaseAgent(t)
	p := startProc(t, a, "sleeper", `exec sleep 3002`, 0)
	for i := range 3 {
		out, stderr, end, errMsg := drive(t, a, leaseReq(`sleep 300 & echo hi`), nil)
		if errMsg != "" || end.ExitCode != 0 || out != "hi\n" {
			t.Fatalf("Exec %d: end %+v, err %q, stdout %q, stderr %q", i, end, errMsg, out, stderr)
		}
		if len(end.Tracked) != 1 || end.Tracked[0].ID != p.ID || end.Tracked[0].State != TrackedRunning || end.Tracked[0].Name != "sleeper" {
			t.Errorf("Exec %d End.Tracked %+v, want the running sleeper", i, end.Tracked)
		}
		if !pidAlive(p.PID) {
			t.Fatalf("the tracked process %d died with Exec %d's teardown", p.PID, i)
		}
		if !slices.Contains(cgroupProcs(t, filepath.Join(root, "tracked", "p"+p.ID)), p.PID) {
			t.Fatalf("pid %d left tracked/p%s", p.PID, p.ID)
		}
	}
	// The Execs' own background sleeps went with their cgroups.
	if left := procsMatching(t, regexp.MustCompile(`^sleep 300$`), 7000); len(left) > 0 {
		t.Errorf("Exec processes survived: %v", left)
	}
}

// Review Focus 1: a tracked process that double-forks a daemon keeps it in its cgroup.
// Execs do not kill it, process_list shows only the original entry, and process_stop
// kills the daemon too.
func TestTrackedDoubleForkStaysInCgroup(t *testing.T) {
	a, root := newLeaseAgent(t)
	p := startProc(t, a, "forker", `( setsid bash -c 'sleep 3011 &' ); exec sleep 3010`, 0)
	daemon := waitPidOf(t, regexp.MustCompile(`^sleep 3011$`), trackedUID0)
	cg := filepath.Join(root, "tracked", "p"+p.ID)
	if procs := cgroupProcs(t, cg); !slices.Contains(procs, daemon) || !slices.Contains(procs, p.PID) {
		t.Fatalf("%s holds %v; want the main %d and the daemon %d", cg, procs, p.PID, daemon)
	}
	if _, _, end, errMsg := drive(t, a, leaseReq(`true`), nil); errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("Exec: end %+v, err %q", end, errMsg)
	}
	if !pidAlive(daemon) {
		t.Fatal("an Exec's teardown killed the tracked daemon")
	}
	if ps := listProcs(t, a); len(ps) != 1 || ps[0].ID != p.ID || ps[0].PID != p.PID {
		t.Errorf("process_list %+v, want only the original entry", ps)
	}
	final := stopProc(t, a, ProcessArgs{ID: p.ID})
	if final.State != TrackedKilled || final.Code != int(syscall.SIGTERM) {
		t.Errorf("final state %+v, want killed(15)", final)
	}
	waitPidsGone(t, "process_stop", p.PID, daemon)
}

// Review Focus 2: a later Exec cannot signal, ptrace, process_vm_writev or write the
// /proc/<pid>/mem of a running tracked process, and its argv and memory are unchanged.
// The probe runs twice: as an Exec (uid split plus seccomp), and as uid 7000 with no
// seccomp, which shows the uid split alone refuses all four.
const attackTrackedScript = `
import ctypes, os, sys
pid = int(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
try:
    os.kill(pid, 19)  # SIGSTOP
    print("kill ok")
except OSError as e:
    print("kill", e.errno)
libc.ptrace.restype = ctypes.c_long
ctypes.set_errno(0)
r = libc.ptrace(16, pid, None, None)  # PTRACE_ATTACH
print("ptrace", "ok" if r != -1 else ctypes.get_errno())
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
buf = ctypes.create_string_buffer(b"XXXXXXXX", 8)
local = iovec(ctypes.cast(buf, ctypes.c_void_p), 8)
remote = iovec(ctypes.c_void_p(0x400000), 8)
libc.process_vm_writev.restype = ctypes.c_ssize_t
ctypes.set_errno(0)
r = libc.process_vm_writev(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
print("process_vm_writev", "ok" if r != -1 else ctypes.get_errno())
try:
    fd = os.open("/proc/%d/mem" % pid, os.O_RDWR)
    print("mem ok")
except OSError as e:
    print("mem", e.errno)
`

func checkAttackRefused(t *testing.T, who, out string) {
	t.Helper()
	for _, step := range []string{"kill", "ptrace", "process_vm_writev", "mem"} {
		m := regexp.MustCompile(`(?m)^` + step + ` (\S+)$`).FindStringSubmatch(out)
		// EPERM (1) or EACCES (13): refused at the permission check, not by a bad address.
		if m == nil || (m[1] != "1" && m[1] != "13") {
			t.Errorf("%s: %s: %v, want refused with EPERM or EACCES\n%s", who, step, m, out)
		}
	}
}

func TestExecCannotTouchTrackedProcess(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3")
	}
	a, _ := newLeaseAgent(t)
	p := startProc(t, a, "victim", `v=intact; while :; do echo "v=$v"; sleep 0.1; done`, 0)
	waitLog(t, a, p.ID, "v=intact")
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.PID))
	if err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(a.WorkDir(), "attack.py")
	if err := os.WriteFile(script, []byte(attackTrackedScript), 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr, end, errMsg := drive(t, a, leaseReq(fmt.Sprintf(`python3 attack.py %d`, p.PID)), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("attack Exec: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	t.Logf("as an Exec:\n%s", out)
	checkAttackRefused(t, "Exec", out)

	probe := exec.Command("python3", script, strconv.Itoa(p.PID))
	probe.Dir = "/"
	probe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 7000, Gid: 7000, Groups: []uint32{7000}}}
	pout, err := probe.CombinedOutput()
	if err != nil {
		t.Fatalf("uid-7000 probe: %v\n%s", err, pout)
	}
	t.Logf("as uid 7000 without seccomp:\n%s", pout)
	checkAttackRefused(t, "uid 7000 without seccomp", string(pout))

	if !pidAlive(p.PID) {
		t.Fatal("the tracked process died")
	}
	if st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.PID)); strings.Contains(string(st), ") T ") {
		t.Fatal("the tracked process was stopped")
	}
	if now, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.PID)); string(now) != string(cmdline) {
		t.Errorf("argv changed: %q, was %q", now, cmdline)
	}
	// Still printing, and only what it printed before: three more lines at least.
	before, _ := procLogs(t, a, ProcessArgs{ID: p.ID, Tail: 100000})
	after := before
	for deadline := time.Now().Add(5 * time.Second); strings.Count(after, "\n") < strings.Count(before, "\n")+3; {
		if time.Now().After(deadline) {
			t.Fatal("the tracked process stopped printing")
		}
		time.Sleep(50 * time.Millisecond)
		after, _ = procLogs(t, a, ProcessArgs{ID: p.ID, Tail: 100000})
	}
	for _, line := range strings.Split(strings.TrimSpace(after), "\n") {
		if line != "v=intact" {
			t.Fatalf("the tracked process's output changed: %q", line)
		}
	}
}

// Review Focus 3: a tracked process that OOMs inside its cgroup shows killed(9), and
// the lease survives: the next Exec runs. The test lowers memory.max on the tracked
// cgroup, then lets the process allocate.
func TestTrackedOOMKeepsTheLease(t *testing.T) {
	a, root := newLeaseAgent(t)
	p := startProc(t, a, "hog", `while [ ! -e go ]; do sleep 0.05; done; x=$(head -c 400000000 /dev/zero | tr '\0' a); echo survived`, 0)
	cg := filepath.Join(root, "tracked", "p"+p.ID)
	if err := os.WriteFile(filepath.Join(cg, "memory.max"), []byte("33554432"), 0); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(cg, "memory.swap.max"), []byte("0"), 0)
	if err := os.WriteFile(filepath.Join(a.WorkDir(), "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	final := waitProcExit(t, a, p.ID)
	if final.State != TrackedKilled || final.Code != 9 {
		t.Fatalf("hog %+v, want killed(9)", final)
	}
	out, stderr, end, errMsg := drive(t, a, leaseReq(`echo ok`), nil)
	if errMsg != "" || end.ExitCode != 0 || out != "ok\n" || end.TeardownFailed {
		t.Fatalf("Exec after the OOM: end %+v, err %q, stdout %q, stderr %q", end, errMsg, out, stderr)
	}
	if logs, _ := procLogs(t, a, ProcessArgs{Name: "hog"}); strings.Contains(logs, "survived") {
		t.Errorf("the hog was not killed: %q", logs)
	}
}

// Spec §3.3: a tracked uid is not reused while its cgroup is populated, even once its
// process has exited and left a child behind; the allocator's refusal is process_limit.
func TestTrackedUIDNotReusedWhilePopulated(t *testing.T) {
	a, _ := newLeaseAgentWith(t, func(lo *LeaseOptions) { lo.MaxTrackedUIDs = 2 })
	p1 := startProc(t, a, "leaver", `( setsid sleep 3020 & ); exit 0`, 0)
	if st := waitProcExit(t, a, p1.ID); st.State != TrackedExited || st.Code != 0 {
		t.Fatalf("leaver %+v, want exited(0)", st)
	}
	left := waitPidOf(t, regexp.MustCompile(`^sleep 3020$`), trackedUID0)
	// Its uid is read once the shim has exec'd the command, so after the drop.
	p2 := startProc(t, a, "", `exec sleep 3021`, 0)
	if uid := procUID(fmt.Sprintf("/proc/%d", waitPidOf(t, regexp.MustCompile(`^sleep 3021$`), -1))); uid != trackedUID1 {
		t.Fatalf("second process runs as %d, want 20001: 20000 is still populated", uid)
	}
	// One running of four allowed, but no uid is free: 20000 still holds the leftover.
	if _, errMsg := tryStartProc(t, a, ProcessArgs{}, `exec sleep 3022`, 0); errMsg != "process_limit: 4 running (SH_LEASE_MAX_PROCESSES)" {
		t.Fatalf("third start: %q, want the process_limit refusal", errMsg)
	}
	stopProc(t, a, ProcessArgs{ID: p2.ID})
	startProc(t, a, "", `exec sleep 3023`, 0)
	if uid := procUID(fmt.Sprintf("/proc/%d", waitPidOf(t, regexp.MustCompile(`^sleep 3023$`), -1))); uid != trackedUID1 {
		t.Fatalf("after stopping 20001's process, the next runs as %d, want 20001 (20000 is still populated)", uid)
	}
	// process_stop of the exited entry kills what it left, which frees 20000.
	if st := stopProc(t, a, ProcessArgs{Name: "leaver"}); st.State != TrackedExited || st.Code != 0 {
		t.Errorf("stopping the exited leaver answered %+v, want its exited(0)", st)
	}
	waitPidsGone(t, "process_stop of an exited entry", left)
	startProc(t, a, "", `exec sleep 3024`, 0)
	if uid := procUID(fmt.Sprintf("/proc/%d", waitPidOf(t, regexp.MustCompile(`^sleep 3024$`), -1))); uid != trackedUID0 {
		t.Fatalf("after the leftover is gone, the next runs as %d, want 20000", uid)
	}
}

// SH_LEASE_MAX_PROCESSES counts running processes only.
func TestProcessLimitCountsRunningOnly(t *testing.T) {
	a, _ := newLeaseAgent(t)
	startProc(t, a, "a", `exec sleep 3030`, 2)
	b := startProc(t, a, "b", `exit 3`, 2)
	if st := waitProcExit(t, a, b.ID); st.State != TrackedExited || st.Code != 3 {
		t.Fatalf("b %+v, want exited(3)", st)
	}
	startProc(t, a, "c", `exec sleep 3031`, 2)
	if _, errMsg := tryStartProc(t, a, ProcessArgs{Name: "d"}, `exec sleep 3032`, 2); errMsg != "process_limit: 2 running (SH_LEASE_MAX_PROCESSES)" {
		t.Fatalf("third running process: %q, want process_limit: 2 running (SH_LEASE_MAX_PROCESSES)", errMsg)
	}
	if ps := listProcs(t, a); len(ps) != 3 {
		t.Errorf("process_list %+v, want a, b and c", ps)
	}
}

// process_stop sends the signal (TERM by default) to the process's cgroup, waits out
// the grace, then kills the cgroup.
func TestProcessStopTermThenKill(t *testing.T) {
	a, _ := newLeaseAgent(t)
	if trackedStopGrace != 10*time.Second {
		t.Fatalf("trackedStopGrace %s, want 10s (global constraints)", trackedStopGrace)
	}
	orig := trackedStopGrace
	trackedStopGrace = time.Second
	t.Cleanup(func() { trackedStopGrace = orig })

	stubborn := startProc(t, a, "stubborn", `trap '' TERM; echo ready; while :; do sleep 0.1; done`, 0)
	waitLog(t, a, stubborn.ID, "ready")
	start := time.Now()
	final := stopProc(t, a, ProcessArgs{Name: "stubborn"})
	if el := time.Since(start); el < time.Second || el > 4*time.Second {
		t.Errorf("stopping a TERM-ignoring process took %s, want the 1s grace and then the kill", el)
	}
	if final.State != TrackedKilled || final.Code != 9 || final.ID != stubborn.ID {
		t.Errorf("final state %+v, want killed(9)", final)
	}
	waitPidsGone(t, "the stubborn process", stubborn.PID)

	polite := startProc(t, a, "polite", `exec sleep 3040`, 0)
	start = time.Now()
	if final := stopProc(t, a, ProcessArgs{ID: polite.ID}); final.State != TrackedKilled || final.Code != int(syscall.SIGTERM) {
		t.Errorf("final state %+v, want killed(15)", final)
	}
	if el := time.Since(start); el >= time.Second {
		t.Errorf("stopping a TERM-honouring process took %s, want well under the grace", el)
	}

	sig := startProc(t, a, "", `exec sleep 3041`, 0)
	if final := stopProc(t, a, ProcessArgs{ID: sig.ID, Signal: "INT"}); final.State != TrackedKilled || final.Code != int(syscall.SIGINT) {
		t.Errorf("signal INT: final state %+v, want killed(2)", final)
	}
	if _, _, _, errMsg := drive(t, a, procReq(RequestKindProcessStop, ProcessArgs{ID: sig.ID, Signal: "NOPE"}), nil); !strings.Contains(errMsg, "unknown signal NOPE") {
		t.Errorf("signal NOPE: %q, want an unknown signal refusal", errMsg)
	}
	if _, _, _, errMsg := drive(t, a, procReq(RequestKindProcessStop, ProcessArgs{Name: "ghost"}), nil); errMsg != "process_not_found: ghost" {
		t.Errorf("stop ghost: %q, want process_not_found: ghost", errMsg)
	}
}

// A stop right after a start ends the process with the signal, under the agent's own
// signal setup: cmd/guest-agent ignores TERM, INT and HUP, so the shim starts with
// them ignored, and a TERM that landed before the shim's exec would be dropped and the
// stop would wait out the grace and kill. process_start answers only once the command
// has replaced the shim (its exec barrier), and the shim resets what it inherited.
func TestProcessStopRightAfterStartDeliversTheSignal(t *testing.T) {
	a, _ := newLeaseAgent(t)
	// As cmd/guest-agent, and as TestAgentSurvivesTrapKillPPIDOnExit (Reset does not
	// undo Ignore, so later tests in this binary run under it too, as in a guest).
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	t.Cleanup(func() { signal.Reset(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP) })
	orig := trackedStopGrace
	trackedStopGrace = 3 * time.Second
	t.Cleanup(func() { trackedStopGrace = orig })
	for i := range 20 {
		p := startProc(t, a, "", `exec sleep 3100`, 0)
		start := time.Now()
		final := stopProc(t, a, ProcessArgs{ID: p.ID})
		if el := time.Since(start); final.State != TrackedKilled || final.Code != int(syscall.SIGTERM) || el > 2*time.Second {
			t.Fatalf("round %d: stop right after start: %+v in %s, want killed(15) well inside the grace", i, final, el)
		}
	}
}

// The cwd must resolve inside the workspace, with no symlink escape.
func TestProcessCwdMustStayInWorkspace(t *testing.T) {
	a, _ := newLeaseAgent(t)
	work := a.WorkDir()
	if err := os.Mkdir(filepath.Join(work, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(work, "esc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(work, "in")); err != nil {
		t.Fatal(err)
	}
	for _, cwd := range []string{"/etc", work + "/..", "esc", filepath.Join(work, "esc"), "nope", "../" + filepath.Base(work) + "x"} {
		if _, errMsg := tryStartProc(t, a, ProcessArgs{Cwd: cwd}, `touch /tmp/never; pwd`, 0); !strings.HasPrefix(errMsg, "process_cwd: ") {
			t.Errorf("cwd %q: %q, want a process_cwd: refusal", cwd, errMsg)
		}
	}
	if ps := listProcs(t, a); len(ps) != 0 {
		t.Errorf("refused starts left entries: %+v", ps)
	}
	for cwd, want := range map[string]string{"": work, "sub": work + "/sub", "in": work + "/sub", work + "/in": work + "/sub"} {
		p, errMsg := tryStartProc(t, a, ProcessArgs{Cwd: cwd}, `pwd -P`, 0)
		if errMsg != "" {
			t.Errorf("cwd %q: %s", cwd, errMsg)
			continue
		}
		waitProcExit(t, a, p.ID)
		if out, _ := procLogs(t, a, ProcessArgs{ID: p.ID}); out != want+"\n" {
			t.Errorf("cwd %q: pwd %q, want %q", cwd, out, want)
		}
	}
}

// Spec §3.3: the sbx-ws group and umask 0002 let a later Exec edit what a tracked
// process wrote in the (setgid, group-writable) workspace.
func TestTrackedFileEditableByLaterExec(t *testing.T) {
	a, _ := newLeaseAgent(t)
	if err := os.Chown(a.WorkDir(), 7000, 7000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.WorkDir(), 0o2775); err != nil {
		t.Fatal(err)
	}
	p := startProc(t, a, "writer", `mkdir -p build && echo one > build/out.txt`, 0)
	if st := waitProcExit(t, a, p.ID); st.State != TrackedExited || st.Code != 0 {
		logs, _ := procLogs(t, a, ProcessArgs{ID: p.ID})
		t.Fatalf("writer %+v, want exited(0); logs %q", st, logs)
	}
	out := filepath.Join(a.WorkDir(), "build", "out.txt")
	if uid, gid, mode := statOwner(t, out); uid != trackedUID0 || gid != 7000 || mode&0o777 != 0o664 {
		t.Errorf("out.txt %d:%d %o, want 20000:7000 0664", uid, gid, mode&0o777)
	}
	_, stderr, end, errMsg := drive(t, a, leaseReq(`echo two >> build/out.txt && touch build/new`), nil)
	if errMsg != "" || end.ExitCode != 0 {
		t.Fatalf("the Exec could not edit the tracked process's file: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	if got, _ := os.ReadFile(out); string(got) != "one\ntwo\n" {
		t.Errorf("out.txt = %q, want one, two", got)
	}
}

// process_logs answers the ring's tail (default 200 lines), stdout and stderr together;
// an unnamed process is shown and found as p<id>; process_list is a JSON array even
// when empty.
func TestProcessLogsAndNames(t *testing.T) {
	a, _ := newLeaseAgent(t)
	if ps := listProcs(t, a); len(ps) != 0 {
		t.Fatalf("a fresh lease lists %+v", ps)
	}
	p := startProc(t, a, "", `for i in $(seq 1 500); do echo line$i; done; echo oops >&2`, 0)
	if p.Name != "p"+p.ID {
		t.Errorf("an unnamed process is named %q, want p%s", p.Name, p.ID)
	}
	waitProcExit(t, a, p.ID)
	if out, errMsg := procLogs(t, a, ProcessArgs{ID: p.ID, Tail: 3}); errMsg != "" || out != "line499\nline500\noops\n" {
		t.Errorf("tail 3: %q, %q", out, errMsg)
	}
	out, errMsg := procLogs(t, a, ProcessArgs{Name: "p" + p.ID})
	if errMsg != "" || strings.Count(out, "\n") != 200 || !strings.HasPrefix(out, "line302\n") {
		t.Errorf("default tail by display name: %d lines from %.10q, err %q; want 200 from line302", strings.Count(out, "\n"), out, errMsg)
	}
	if ps := listProcs(t, a); len(ps) != 1 || ps[0].Name != "p"+p.ID {
		t.Errorf("process_list %+v, want the unnamed process shown as p%s", ps, p.ID)
	}
	if _, errMsg := procLogs(t, a, ProcessArgs{Name: "nope"}); errMsg != "process_not_found: nope" {
		t.Errorf("logs of nope: %q", errMsg)
	}

	startProc(t, a, "web", `exec sleep 3050`, 0)
	if _, errMsg := tryStartProc(t, a, ProcessArgs{Name: "web"}, `exec sleep 3051`, 0); errMsg != "process_name_taken: web" {
		t.Errorf("second web: %q, want process_name_taken: web", errMsg)
	}
	if _, errMsg := tryStartProc(t, a, ProcessArgs{Name: "a b"}, `true`, 0); !strings.HasPrefix(errMsg, "process_name_invalid: ") {
		t.Errorf("name 'a b': %q, want process_name_invalid:", errMsg)
	}
}

// process_stop_all (host-only) stops every running process and anything an exited one
// left behind, and answers the final states of the processes that were running.
func TestProcessStopAllStopsEveryProcessAndLeftover(t *testing.T) {
	a, root := newLeaseAgent(t)
	leaver := startProc(t, a, "leaver", `( setsid sleep 3060 & ); exit 0`, 0)
	waitProcExit(t, a, leaver.ID)
	left := waitPidOf(t, regexp.MustCompile(`^sleep 3060$`), trackedUID0)
	a1 := startProc(t, a, "a1", `exec sleep 3061`, 0)
	a2 := startProc(t, a, "a2", `exec sleep 3062`, 0)
	out, stderr, end, errMsg := drive(t, a, procReq(RequestKindProcessStopAll, ProcessArgs{}), nil)
	if errMsg != "" || end.TeardownFailed {
		t.Fatalf("process_stop_all: end %+v, err %q, stderr %q", end, errMsg, stderr)
	}
	var stopped []TrackedProcess
	if err := json.Unmarshal([]byte(out), &stopped); err != nil {
		t.Fatalf("process_stop_all stdout %q: %v", out, err)
	}
	if len(stopped) != 2 || stopped[0].ID != a1.ID || stopped[1].ID != a2.ID {
		t.Errorf("stopped %+v, want a1 and a2", stopped)
	}
	for _, s := range stopped {
		if s.State != TrackedKilled || s.Code != int(syscall.SIGTERM) {
			t.Errorf("stopped %+v, want killed(15)", s)
		}
	}
	waitPidsGone(t, "process_stop_all", a1.PID, a2.PID, left)
	for _, tp := range end.Tracked {
		if tp.State == TrackedRunning {
			t.Errorf("End.Tracked after stop_all still has %+v running", tp)
		}
	}
	if pcs, _ := filepath.Glob(filepath.Join(root, "tracked", "p[0-9]*")); len(pcs) != 0 {
		t.Errorf("tracked cgroups left after stop_all: %v", pcs)
	}
	if out, _, _, errMsg := drive(t, a, procReq(RequestKindProcessStopAll, ProcessArgs{}), nil); errMsg != "" || out != "[]" {
		t.Errorf("stop_all with nothing running: %q, %q; want []", out, errMsg)
	}
}

// A cgroup that does not empty after the kill answers End{TeardownFailed}, and the agent
// is dead, as for an Exec.
func TestProcessStopTeardownFailureMarksTheAgentDead(t *testing.T) {
	a, _ := newLeaseAgent(t)
	p := startProc(t, a, "", `exec sleep 3070`, 0)
	orig := waitCgroupEmpty
	waitCgroupEmpty = func(*execCgroup, time.Duration) error { return errors.New("injected: still populated") }
	t.Cleanup(func() { waitCgroupEmpty = orig })
	_, _, end, errMsg := drive(t, a, procReq(RequestKindProcessStop, ProcessArgs{ID: p.ID}), nil)
	if errMsg != "" || !end.TeardownFailed {
		t.Fatalf("end %+v, err %q; want teardown_failed", end, errMsg)
	}
	if _, _, _, errMsg := drive(t, a, leaseReq(`true`), nil); !strings.Contains(errMsg, "teardown failed") {
		t.Fatalf("next request's error %q, want it to say teardown failed", errMsg)
	}
}

// Ruling P5-R9 and the strict rule: an entry the table drops (the ninth exit evicts the
// oldest exited; a new process takes an exited one's name) leaves nothing running, and
// its uid is free again once its cgroup is empty.
func TestTrackedDroppedEntryLeavesNothingRunning(t *testing.T) {
	a, root := newLeaseAgent(t)
	old := startProc(t, a, "web", `( setsid sleep 3080 & ); exit 0`, 0)
	waitProcExit(t, a, old.ID)
	left := waitPidOf(t, regexp.MustCompile(`^sleep 3080$`), trackedUID0)
	if !pidAlive(left) {
		t.Fatal("the leftover is not running")
	}
	// Replacing the name drops the exited entry, and with it what it left.
	repl := startProc(t, a, "web", `exec sleep 3081`, 0)
	waitPidsGone(t, "the replaced entry's leftover", left)
	if ps := listProcs(t, a); len(ps) != 1 || ps[0].ID != repl.ID {
		t.Errorf("process_list %+v, want only the new web", ps)
	}
	if _, err := os.Stat(filepath.Join(root, "tracked", "p"+old.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the replaced entry's cgroup is still there (stat err %v)", err)
	}

	// Eviction: one exited leaver, then trackedExitedKeep more exits evict it.
	ev := startProc(t, a, "ev", `( setsid sleep 3082 & ); exit 0`, 0)
	waitProcExit(t, a, ev.ID)
	evLeft := waitPidOf(t, regexp.MustCompile(`^sleep 3082$`), -1)
	for range trackedExitedKeep {
		p := startProc(t, a, "", `exit 0`, 0)
		waitProcExit(t, a, p.ID)
	}
	if _, ok := procByID(listProcs(t, a), ev.ID); ok {
		t.Fatalf("entry %s was not evicted", ev.ID)
	}
	waitPidsGone(t, "the evicted entry's leftover", evLeft)
}

// Ruling P5-R6: an unknown kind is refused and never runs as a command.
func TestLeaseUnknownKindIsRefusedNotRun(t *testing.T) {
	a, _ := newLeaseAgent(t)
	marker := filepath.Join(a.WorkDir(), "ran")
	req := leaseReq(`touch ` + marker)
	req.Kind = "process_restart"
	if _, _, _, errMsg := drive(t, a, req, nil); errMsg != "lease_unsupported: unknown kind process_restart" {
		t.Fatalf("error %q, want lease_unsupported: unknown kind process_restart", errMsg)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the unknown kind ran as a command (stat err %v)", err)
	}
}

// A start that fails after its uid was taken releases the uid and leaves no cgroup: with
// one tracked uid, the next start still gets it.
func TestProcessStartFailureReleasesItsUID(t *testing.T) {
	a, root := newLeaseAgentWith(t, func(lo *LeaseOptions) { lo.MaxTrackedUIDs = 1 })
	good := trackedHomeParent
	trackedHomeParent = filepath.Join(t.TempDir(), "missing")
	_, errMsg := tryStartProc(t, a, ProcessArgs{Name: "x"}, `exec sleep 3090`, 0)
	trackedHomeParent = good
	if !strings.Contains(errMsg, "home") {
		t.Fatalf("start with no home parent: %q, want a home error", errMsg)
	}
	if pcs, _ := filepath.Glob(filepath.Join(root, "tracked", "p[0-9]*")); len(pcs) != 0 {
		t.Errorf("a failed start left cgroups %v", pcs)
	}
	if ps := listProcs(t, a); len(ps) != 0 {
		t.Errorf("a failed start left entries %+v", ps)
	}
	p := startProc(t, a, "x", `exec sleep 3091`, 0)
	if uid := procUID(fmt.Sprintf("/proc/%d", waitPidOf(t, regexp.MustCompile(`^sleep 3091$`), -1))); uid != trackedUID0 {
		t.Fatalf("the start after a failed one runs as %d, want 20000", uid)
	}
	stopProc(t, a, ProcessArgs{ID: p.ID})
}
