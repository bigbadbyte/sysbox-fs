//
// Copyright 2026 sysbox community contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package seccomp

import (
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sys/unix"
)

// fakeProc is a ProcessIface with just a pid and a user-ns inode.
type fakeProc struct {
	domain.ProcessIface
	pid    uint32
	userns domain.Inode
	err    error
}

func (p *fakeProc) Pid() uint32                        { return p.pid }
func (p *fakeProc) UserNsInode() (domain.Inode, error) { return p.userns, p.err }

func TestInNestedUserns(t *testing.T) {
	const cntrUserns = 100
	tests := []struct {
		proc    domain.ProcessIface
		want    bool
		wantErr bool
	}{
		{&fakeProc{pid: 5, userns: cntrUserns}, false, false},
		{&fakeProc{pid: 5, userns: 200}, true, false},
		{&fakeProc{pid: 5, err: syscall.ESRCH}, false, true},
		{nil, false, false},
	}
	for i, tt := range tests {
		got, err := inNestedUserns(tt.proc, cntrUserns)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("case %d: got %v, %v", i, got, err)
		}
	}
}

// The container's user ns is the owner of the container's pid ns, even when
// the container's init itself moved to a nested user ns (e.g. its entrypoint
// is `unshare -U ...`).
func TestContainerUserns(t *testing.T) {
	owner := func(pid uint32, ns domain.NStype) (domain.Inode, error) {
		if pid != 42 || ns != domain.NStypePid {
			t.Errorf("owner(%d, %s)", pid, ns)
		}
		return 100, nil
	}
	got, err := containerUserns(&fakeProc{pid: 42, userns: 200}, owner)
	if err != nil || got != 100 {
		t.Fatalf("containerUserns = %d, %v; want the pid ns owner 100", got, err)
	}
	if _, err := containerUserns(nil, owner); err == nil {
		t.Fatal("no init process must be an error")
	}
	failing := func(uint32, domain.NStype) (domain.Inode, error) { return 0, syscall.ESRCH }
	if _, err := containerUserns(&fakeProc{pid: 42}, failing); err == nil {
		t.Fatal("owner lookup errors must be returned")
	}
}

// nsOwner/openNsOwner on our own process: the owner of our pid ns is our
// user ns (we haven't unshared anything).
func TestNsOwnerSelf(t *testing.T) {
	ino, err := nsOwner(uint32(os.Getpid()), domain.NStypePid)
	if err != nil {
		t.Skipf("NS_GET_USERNS not available: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/user", &st); err != nil {
		t.Fatal(err)
	}
	if ino != st.Ino {
		t.Errorf("pid ns owner = %d, want our user ns %d", ino, st.Ino)
	}
	if _, err := openNsOwner(0, domain.NStypePid); err == nil {
		t.Error("pid 0 must fail")
	}
}

// fakeParser serves a fixed mount list.
type fakeParser struct {
	domain.MountInfoParserIface
	mounts []*domain.MountInfo
	ro     map[string]bool
}

func (f *fakeParser) AllMounts() []*domain.MountInfo { return f.mounts }
func (f *fakeParser) GetInfo(mp string) *domain.MountInfo {
	for _, m := range f.mounts {
		if m.MountPoint == mp {
			return m
		}
	}
	return nil
}
func (f *fakeParser) IsRoMount(m *domain.MountInfo) bool { return f.ro[m.MountPoint] }

// fakeCntr is a ContainerIface with just an init process (the generated
// mocks.ContainerIface is out of date with the interface).
type fakeCntr struct {
	domain.ContainerIface
	init    domain.ProcessIface
	mntns   *os.File
	initial []*domain.MountInfo
}

func (c *fakeCntr) InitProc() domain.ProcessIface      { return c.init }
func (c *fakeCntr) MountNsFile() *os.File              { return c.mntns }
func (c *fakeCntr) InitialMounts() []*domain.MountInfo { return c.initial }

// ro marks a mount read-only (as InitialMounts reports it).
func ro(m *domain.MountInfo) *domain.MountInfo {
	c := *m
	c.Options = map[string]string{"ro": ""}
	return &c
}

// fakeTreeEvent is an nsenter event that can carry a tree fd.
type fakeTreeEvent struct {
	domain.NSenterEventIface
	nsPid  map[domain.NStype]uint32
	nsFile map[domain.NStype]*os.File
	treeFd int
}

func (e *fakeTreeEvent) SetNamespacePid(ns domain.NStype, pid uint32) {
	if e.nsPid == nil {
		e.nsPid = map[domain.NStype]uint32{}
	}
	e.nsPid[ns] = pid
}
func (e *fakeTreeEvent) SetNamespaceFile(ns domain.NStype, f *os.File) {
	if e.nsFile == nil {
		e.nsFile = map[domain.NStype]*os.File{}
	}
	e.nsFile[ns] = f
}
func (e *fakeTreeEvent) TreeFd() int      { return e.treeFd }
func (e *fakeTreeEvent) SetTreeFd(fd int) { e.treeFd = fd }

// realisticOwners: the container (init pid 42) is user ns 100; the
// requester (pid 1234) unshared user ns 200 and, with it, its own pid and net
// namespaces (like `unshare -Upn` or bwrap --unshare-all).
func realisticOwners(pid uint32, ns domain.NStype) (domain.Inode, error) {
	if pid == 1234 && (ns == domain.NStypePid || ns == domain.NStypeNet) {
		return 200, nil
	}
	return 100, nil
}

type nestedFixture struct {
	m   *mountSyscallInfo
	nss *mocks.NSenterServiceIface
}

// newNestedFixture: container init pid 42; requester pid 1234; the
// container's mounts are containerProc + containerSys.
func newNestedFixture(t *testing.T, fsType string, requester []*domain.MountInfo) (*nestedFixture, *fakeParser) {
	t.Helper()
	nss := &mocks.NSenterServiceIface{}

	init := &fakeProc{pid: 42, userns: 100}
	var initial []*domain.MountInfo
	for _, m := range append(append([]*domain.MountInfo{}, containerProc...), containerSys[1:]...) {
		if m.MountPoint == "/proc/bus" || m.MountPoint == "/sys/firmware" {
			m = ro(m)
		}
		initial = append(initial, m)
	}
	cntr := &fakeCntr{init: init, initial: initial}

	svc := &SyscallMonitorService{nss: nss}
	svc.nsOwnerFn = realisticOwners
	svc.openNsOwnerFn = func(uint32, domain.NStype) (*os.File, error) { return os.Open("/dev/null") }
	tracer := &syscallTracer{service: svc}
	svc.tracer = tracer

	m := &mountSyscallInfo{
		syscallCtx: syscallCtx{reqId: 7, pid: 1234, cntr: cntr, tracer: tracer,
			processInfo: &fakeProc{pid: 1234, userns: 200}},
		MountSyscallPayload: &domain.MountSyscallPayload{
			Mount: domain.Mount{Source: fsType, Target: "/x", FsType: fsType, Flags: unix.MS_NOSUID},
		},
	}
	return &nestedFixture{m: m, nss: nss}, &fakeParser{mounts: requester}
}

func TestContainerMountNs(t *testing.T) {
	held, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	f, _ := newNestedFixture(t, "proc", nil)
	cntr := f.m.cntr.(*fakeCntr)

	// held fd wins
	cntr.mntns = held
	if got, err := f.m.containerMountNs(); err != nil || got != held {
		t.Fatalf("held: got %v, %v", got, err)
	}

	// not held, init still in the container's mount ns: use init's (nil)
	cntr.mntns = nil
	if got, err := f.m.containerMountNs(); err != nil || got != nil {
		t.Fatalf("fallback: got %v, %v", got, err)
	}

	// not held, init moved to a mount ns owned by a nested user ns: refuse
	f.m.tracer.service.nsOwnerFn = func(pid uint32, ns domain.NStype) (domain.Inode, error) {
		if pid == 42 && ns == domain.NStypeMount {
			return 300, nil
		}
		return realisticOwners(pid, ns)
	}
	if _, err := f.m.containerMountNs(); err == nil {
		t.Fatal("init outside the container's mount ns, nothing held: must refuse")
	}

	// lookup errors propagate
	f.m.tracer.service.nsOwnerFn = func(uint32, domain.NStype) (domain.Inode, error) { return 0, syscall.ESRCH }
	if _, err := f.m.containerMountNs(); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("want ESRCH, got %v", err)
	}
}

func TestProcessNestedMountRefusesWithoutContainerMountNs(t *testing.T) {
	f, req := newNestedFixture(t, "proc", containerProc)
	f.m.tracer.service.nsOwnerFn = func(pid uint32, ns domain.NStype) (domain.Inode, error) {
		if pid == 42 && ns == domain.NStypeMount {
			return 300, nil
		}
		return realisticOwners(pid, ns)
	}
	resp, err := f.m.processNestedMount(nestedProc, req)
	if err != nil || resp.Error != int32(syscall.EPERM) {
		t.Fatalf("want EPERM response, got %+v, %v", resp, err)
	}
	f.nss.AssertNotCalled(t, "NewEvent", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// The kernel refuses a sysfs (procfs) bound to a net (pid) ns the requester's
// user ns doesn't own, e.g. `unshare -Um` without -n; sysbox must too.
func TestProcessNestedMountRefusesForeignBoundNs(t *testing.T) {
	for _, k := range []nestedKind{nestedSysfs, nestedProc} {
		f, req := newNestedFixture(t, k.fsType, containerSys)
		f.m.tracer.service.nsOwnerFn = func(pid uint32, ns domain.NStype) (domain.Inode, error) {
			if pid == 1234 && ns == k.ns {
				return 100, nil // still the container's
			}
			return realisticOwners(pid, ns)
		}
		resp, err := f.m.processNestedMount(k, req)
		if err != nil || resp.Error != int32(syscall.EPERM) {
			t.Fatalf("%s: want EPERM response, got %+v, %v", k.fsType, resp, err)
		}
		f.nss.AssertNotCalled(t, "NewEvent", mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	}
}

func TestBoundToNestedNsErrors(t *testing.T) {
	f, _ := newNestedFixture(t, "sysfs", nil)
	f.m.tracer.service.nsOwnerFn = func(uint32, domain.NStype) (domain.Inode, error) { return 0, syscall.ESRCH }
	if err := f.m.boundToNestedNs(nestedSysfs); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("want ESRCH, got %v", err)
	}
	f.m.tracer.service.nsOwnerFn = realisticOwners
	f.m.processInfo = &fakeProc{pid: 1234, err: syscall.ESRCH}
	if err := f.m.boundToNestedNs(nestedSysfs); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("want ESRCH, got %v", err)
	}
}

func TestIsNestedMount(t *testing.T) {
	f, _ := newNestedFixture(t, "proc", nil)
	if nested, err := f.m.isNestedMount(); err != nil || !nested {
		t.Fatalf("requester userns 200 vs container 100: got %v, %v", nested, err)
	}
	f.m.processInfo = &fakeProc{pid: 1234, userns: 100}
	if nested, err := f.m.isNestedMount(); err != nil || nested {
		t.Fatalf("same userns: got %v, %v", nested, err)
	}
}

func TestNestedTreePayloadProc(t *testing.T) {
	f, req := newNestedFixture(t, "proc", containerProc) // requester sees the same /proc
	p, err := f.m.nestedTreePayload(nestedProc, req)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	want := &domain.ProcTreeBuildPayload{
		FsType:     "proc",
		Base:       "/proc",
		Flags:      unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
		OverMounts: []string{"/sys", "/uptime", "/kcore", "/bus"},
		RoMounts:   []string{"/bus"},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("payload = %+v\nwant %+v", p, want)
	}
}

func TestNestedTreePayloadSysfs(t *testing.T) {
	f, req := newNestedFixture(t, "sysfs", containerSys)
	p, err := f.m.nestedTreePayload(nestedSysfs, req)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	want := &domain.ProcTreeBuildPayload{
		FsType: "sysfs",
		Base:   "/sys",
		Flags:  unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
		// nested over-mount (powercap on /devices/virtual) comes after its parent
		OverMounts: []string{"/fs/cgroup", "/devices/virtual", "/kernel", "/devices/virtual/powercap", "/firmware"},
		RoMounts:   []string{"/firmware"},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("payload = %+v\nwant %+v", p, want)
	}
}

func TestNestedTreePayloadRefusesExtraOverMount(t *testing.T) {
	req := append(append([]*domain.MountInfo{}, containerProc...), mi(99, 10, "/proc/kmsg", "0:5", "/null"))
	f, parser := newNestedFixture(t, "proc", req)
	if _, err := f.m.nestedTreePayload(nestedProc, parser); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("want EPERM, got %v", err)
	}
}

func TestNestedTreePayloadNoInitialMounts(t *testing.T) {
	m := &mountSyscallInfo{syscallCtx: syscallCtx{cntr: &fakeCntr{}}}
	if _, err := m.nestedTreePayload(nestedProc, &fakeParser{}); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("want EPERM, got %v", err)
	}
}

// The over-mounts to build come from the container's initial mounts, not
// from what init (or anything sharing its mount ns) added later: an extra
// mask that only the requester's view has must make the guard refuse, even if
// the container's current mounts would also show it.
func TestNestedTreePayloadUsesInitialMounts(t *testing.T) {
	req := append(append([]*domain.MountInfo{}, containerProc...), mi(99, 10, "/proc/kmsg", "0:5", "/null"))
	f, parser := newNestedFixture(t, "proc", req)
	if _, err := f.m.nestedTreePayload(nestedProc, parser); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("want EPERM, got %v", err)
	}
}

func isType(tp domain.NSenterMsgType) interface{} {
	return mock.MatchedBy(func(m *domain.NSenterMessage) bool { return m.Type == tp })
}

func testProcessNestedMount(t *testing.T, k nestedKind, requester []*domain.MountInfo) {
	f, req := newNestedFixture(t, k.fsType, requester)

	build := &fakeTreeEvent{treeFd: -1}
	attach := &fakeTreeEvent{treeFd: -1}

	// build: container's user ns (by fd) + private copy of its mount ns,
	// requester's pid (procfs) or net (sysfs) ns
	f.nss.On("NewEvent", uint32(42), uint32(0), uint32(0), mock.Anything, uint32(unix.CLONE_NEWNS),
		isType(domain.ProcTreeBuildRequest), mock.Anything, false).Return(build)
	f.nss.On("SendRequestEvent", build).Run(func(mock.Arguments) {
		fds := make([]int, 2)
		if err := unix.Pipe(fds); err != nil {
			t.Fatal(err)
		}
		unix.Close(fds[1])
		build.treeFd = fds[0]
	}).Return(nil)
	f.nss.On("ReceiveResponseEvent", build).Return(&domain.NSenterMessage{Type: domain.ProcTreeBuildResponse})

	// attach: requester's user + mount ns only
	f.nss.On("NewEvent", uint32(1234), uint32(0), uint32(0), mock.Anything, uint32(0),
		isType(domain.ProcTreeAttachRequest), mock.Anything, false).Return(attach)
	f.nss.On("SendRequestEvent", attach).Return(nil)
	f.nss.On("ReceiveResponseEvent", attach).Return(&domain.NSenterMessage{Type: domain.ProcTreeAttachResponse})

	resp, err := f.m.processNestedMount(k, req)
	if err != nil || resp.Error != 0 {
		t.Fatalf("processNestedMount(%s) = %+v, %v", k.fsType, resp, err)
	}

	bns := f.nss.Calls[0].Arguments.Get(3).(*[]domain.NStype)
	wantNs := []domain.NStype{domain.NStypeUser, k.ns, domain.NStypeMount}
	if k.ns != domain.NStypePid {
		wantNs = append(wantNs, domain.NStypePid) // container's, for /proc/self
	}
	if !reflect.DeepEqual(*bns, wantNs) {
		t.Errorf("build namespaces = %v, want %v", *bns, wantNs)
	}
	if build.nsPid[k.ns] != 1234 {
		t.Errorf("build agent must join the requester's %s ns, got %v", k.ns, build.nsPid)
	}
	if build.nsFile[domain.NStypeUser] == nil {
		t.Errorf("build agent must join the container's user ns by fd")
	}
	if build.nsFile[domain.NStypeMount] != nil {
		t.Errorf("no held mount ns: the build agent must use init's")
	}
	if attach.treeFd != build.treeFd || attach.treeFd < 0 {
		t.Errorf("attach got tree fd %d, build produced %d", attach.treeFd, build.treeFd)
	}
	ans := f.nss.Calls[3].Arguments.Get(3).(*[]domain.NStype)
	if !reflect.DeepEqual(*ans, []domain.NStype{domain.NStypeUser, domain.NStypeMount}) {
		t.Errorf("attach namespaces = %v", *ans)
	}
}

func TestProcessNestedMountHeldMountNs(t *testing.T) {
	f, req := newNestedFixture(t, "proc", containerProc)
	held, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	f.m.cntr.(*fakeCntr).mntns = held

	build := &fakeTreeEvent{treeFd: -1}
	f.nss.On("NewEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		isType(domain.ProcTreeBuildRequest), mock.Anything, false).Return(build)
	f.nss.On("SendRequestEvent", build).Return(nil)
	f.nss.On("ReceiveResponseEvent", build).Return(&domain.NSenterMessage{
		Type: domain.ErrorResponse, Payload: fuse.IOerror{Code: syscall.EIO},
	})
	f.m.processNestedMount(nestedProc, req)

	if build.nsFile[domain.NStypeMount] != held {
		t.Errorf("build agent must join the held container mount ns")
	}
}

func TestProcessNestedMountProc(t *testing.T)  { testProcessNestedMount(t, nestedProc, containerProc) }
func TestProcessNestedMountSysfs(t *testing.T) { testProcessNestedMount(t, nestedSysfs, containerSys) }

func TestProcessNestedMountBuildError(t *testing.T) {
	f, req := newNestedFixture(t, "proc", containerProc)
	build := &fakeTreeEvent{treeFd: -1}
	f.nss.On("NewEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, false).Return(build)
	f.nss.On("SendRequestEvent", build).Return(nil)
	f.nss.On("ReceiveResponseEvent", build).Return(&domain.NSenterMessage{
		Type:    domain.ErrorResponse,
		Payload: fuse.IOerror{Code: syscall.ENOSYS, Message: "fsopen proc: function not implemented"},
	})

	resp, err := f.m.processNestedMount(nestedProc, req)
	if err != nil || resp.Error != int32(syscall.ENOSYS) {
		t.Fatalf("want ENOSYS response, got %+v, %v", resp, err)
	}
}

func TestProcessNestedMountUsernsLookupError(t *testing.T) {
	f, req := newNestedFixture(t, "proc", containerProc)
	f.m.tracer.service.openNsOwnerFn = func(uint32, domain.NStype) (*os.File, error) { return nil, syscall.ESRCH }
	if _, err := f.m.processNestedMount(nestedProc, req); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("want ESRCH error, got %v", err)
	}
}

func TestProcessNestedMountRefusal(t *testing.T) {
	req := append(append([]*domain.MountInfo{}, containerProc...), mi(99, 10, "/proc/kmsg", "0:5", "/null"))
	f, parser := newNestedFixture(t, "proc", req)
	resp, err := f.m.processNestedMount(nestedProc, parser)
	if err != nil || resp.Error != int32(syscall.EPERM) {
		t.Fatalf("want EPERM response, got %+v, %v", resp, err)
	}
	f.nss.AssertNotCalled(t, "NewEvent", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAllMountsNil(t *testing.T) {
	if allMounts(nil) != nil {
		t.Error("nil parser must give nil")
	}
}
