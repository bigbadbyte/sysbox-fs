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
	init := &fakeProc{pid: 1, userns: 100}
	tests := []struct {
		proc    domain.ProcessIface
		want    bool
		wantErr bool
	}{
		{&fakeProc{pid: 5, userns: 100}, false, false},
		{&fakeProc{pid: 5, userns: 200}, true, false},
		{&fakeProc{pid: 5, err: syscall.ESRCH}, false, true},
		{nil, false, false},
	}
	for i, tt := range tests {
		got, err := inNestedUserns(tt.proc, init)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("case %d: got %v, %v", i, got, err)
		}
	}
	if _, err := inNestedUserns(&fakeProc{userns: 1}, &fakeProc{err: syscall.ESRCH}); err == nil {
		t.Error("init error must be returned")
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
	init domain.ProcessIface
}

func (c *fakeCntr) InitProc() domain.ProcessIface { return c.init }

// fakeTreeEvent is an nsenter event that can carry a procfs tree fd.
type fakeTreeEvent struct {
	domain.NSenterEventIface
	nsPid  map[domain.NStype]uint32
	treeFd int
}

func (e *fakeTreeEvent) SetNamespacePid(ns domain.NStype, pid uint32) {
	if e.nsPid == nil {
		e.nsPid = map[domain.NStype]uint32{}
	}
	e.nsPid[ns] = pid
}
func (e *fakeTreeEvent) TreeFd() int      { return e.treeFd }
func (e *fakeTreeEvent) SetTreeFd(fd int) { e.treeFd = fd }

type nestedFixture struct {
	m   *mountSyscallInfo
	nss *mocks.NSenterServiceIface
}

func newNestedFixture(t *testing.T, requester []*domain.MountInfo) (*nestedFixture, *fakeParser) {
	t.Helper()
	nss := &mocks.NSenterServiceIface{}
	mts := &mocks.MountServiceIface{}

	init := &fakeProc{pid: 42, userns: 100}
	cntr := &fakeCntr{init: init}

	cparser := &fakeParser{mounts: containerProc, ro: map[string]bool{"/proc/bus": true}}
	mts.On("NewMountInfoParser", cntr, init, true, true, false).Return(cparser, nil)

	svc := &SyscallMonitorService{nss: nss, mts: mts}
	tracer := &syscallTracer{service: svc}
	svc.tracer = tracer

	m := &mountSyscallInfo{
		syscallCtx: syscallCtx{reqId: 7, pid: 1234, uid: 0, gid: 0, cntr: cntr, tracer: tracer},
		MountSyscallPayload: &domain.MountSyscallPayload{
			Mount: domain.Mount{Source: "proc", Target: "/proc", FsType: "proc", Flags: unix.MS_NOSUID},
		},
	}
	return &nestedFixture{m: m, nss: nss}, &fakeParser{mounts: requester}
}

func TestNestedProcTreePayload(t *testing.T) {
	f, req := newNestedFixture(t, containerProc) // requester sees the same /proc
	p, err := f.m.nestedProcTreePayload(req)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	want := &domain.ProcTreeBuildPayload{
		Flags:      unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
		OverMounts: []string{"/sys", "/uptime", "/kcore", "/bus"},
		RoMounts:   []string{"/bus"},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("payload = %+v\nwant %+v", p, want)
	}
}

func TestNestedProcTreePayloadRefusesExtraOverMount(t *testing.T) {
	req := append(append([]*domain.MountInfo{}, containerProc...), mi(99, 10, "/proc/kmsg", "0:5", "/null"))
	f, parser := newNestedFixture(t, req)
	if _, err := f.m.nestedProcTreePayload(parser); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("want EPERM, got %v", err)
	}
}

func TestNestedProcTreePayloadNoInit(t *testing.T) {
	m := &mountSyscallInfo{syscallCtx: syscallCtx{cntr: &fakeCntr{}}}
	if _, err := m.nestedProcTreePayload(&fakeParser{}); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("want EPERM, got %v", err)
	}
}

func TestProcessNestedProcMount(t *testing.T) {
	f, req := newNestedFixture(t, containerProc)

	build := &fakeTreeEvent{treeFd: -1}
	attach := &fakeTreeEvent{treeFd: -1}
	isType := func(tp domain.NSenterMsgType) interface{} {
		return mock.MatchedBy(func(m *domain.NSenterMessage) bool { return m.Type == tp })
	}

	// build: container init's user/mnt ns (private copy), requester's pid ns
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

	resp, err := f.m.processNestedProcMount(req)
	if err != nil || resp.Error != 0 {
		t.Fatalf("processNestedProcMount = %+v, %v", resp, err)
	}
	if build.nsPid[domain.NStypePid] != 1234 {
		t.Errorf("build agent must join the requester's pid ns, got %v", build.nsPid)
	}
	if attach.treeFd != build.treeFd || attach.treeFd < 0 {
		t.Errorf("attach got tree fd %d, build produced %d", attach.treeFd, build.treeFd)
	}

	ns := f.nss.Calls[3].Arguments.Get(3).(*[]domain.NStype)
	if !reflect.DeepEqual(*ns, []domain.NStype{domain.NStypeUser, domain.NStypeMount}) {
		t.Errorf("attach namespaces = %v", *ns)
	}
}

func TestProcessNestedProcMountBuildError(t *testing.T) {
	f, req := newNestedFixture(t, containerProc)
	build := &fakeTreeEvent{treeFd: -1}
	f.nss.On("NewEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, false).Return(build)
	f.nss.On("SendRequestEvent", build).Return(nil)
	f.nss.On("ReceiveResponseEvent", build).Return(&domain.NSenterMessage{
		Type:    domain.ErrorResponse,
		Payload: fuse.IOerror{Code: syscall.ENOSYS, Message: "fsopen proc: function not implemented"},
	})

	resp, err := f.m.processNestedProcMount(req)
	if err != nil || resp.Error != int32(syscall.ENOSYS) {
		t.Fatalf("want ENOSYS response, got %+v, %v", resp, err)
	}
}

func TestProcessNestedProcMountRefusal(t *testing.T) {
	req := append(append([]*domain.MountInfo{}, containerProc...), mi(99, 10, "/proc/kmsg", "0:5", "/null"))
	f, parser := newNestedFixture(t, req)
	resp, err := f.m.processNestedProcMount(parser)
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
